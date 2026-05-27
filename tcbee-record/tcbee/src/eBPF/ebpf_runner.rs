use std::error::Error;

use aya::{maps::HashMap, Ebpf, EbpfLoader};
use log::{debug, error, info, warn};
use tcbee_common::{
    bindings::{
        tcp_bad_csum::tcp_bad_csum_entry, tcp_probe::tcp_probe_entry,
        tcp_retransmit_synack::tcp_retransmit_synack_entry,
    },
    filter::FilterIp,
};
use tokio::task::{spawn_blocking, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    eBPF::probes::{
        bbr::BBRTracer,
        cubic::CubicTracer,
        cwnd::CwndTracer,
        headers::TCTracer,
        kernel::KernelTracer,
        tracepoints::TracepointTracer,
    },
    viz::ebpf_watcher::EBPFWatcher,
    writer::Writer,
};

use super::ebpf_runner_config::EbpfRunnerConfig;

// TODO: how to handle multiple tracepoints at the same time?
pub struct EbpfRunner {
    stop_token: CancellationToken,
    threads: Vec<JoinHandle<()>>,
    config: EbpfRunnerConfig,
    ebpf: Option<Ebpf>,
    writer: Option<Writer>,
}

pub fn prepend_string(filename: String, dir: &str) -> String {
    std::path::Path::new(dir)
        .join(&filename)
        .to_string_lossy()
        .into_owned()
}

impl EbpfRunner {
    // Load eBPF program and setup references
    pub fn new(stop_token: CancellationToken, config: EbpfRunnerConfig) -> EbpfRunner {
        EbpfRunner {
            stop_token,
            // TODO: new with capacity?
            threads: Vec::new(),
            config,
            ebpf: None,
            writer: None,
        }
    }

    fn insert_filter_ports(
        ebpf: &mut Ebpf,
        map_name: &str,
        ports: &[u16],
    ) -> Result<(), Box<dyn Error>> {
        let mut map: HashMap<_, u16, u8> = HashMap::try_from(
            ebpf.map_mut(map_name)
                .ok_or_else(|| format!("Filter map {} not found", map_name))?,
        )?;
        for port in ports {
            map.insert(*port, 1, 0)?;
        }
        Ok(())
    }

    fn insert_filter_ips(
        ebpf: &mut Ebpf,
        map_name: &str,
        ips: &[[u8; 16]],
    ) -> Result<(), Box<dyn Error>> {
        let mut map: HashMap<_, FilterIp, u8> = HashMap::try_from(
            ebpf.map_mut(map_name)
                .ok_or_else(|| format!("Filter map {} not found", map_name))?,
        )?;
        for ip in ips {
            map.insert(FilterIp { addr: *ip }, 1, 0)?;
        }
        Ok(())
    }

    fn configure_filter(&self, ebpf: &mut Ebpf) -> Result<(), Box<dyn Error>> {
        Self::insert_filter_ports(ebpf, "FILTER_ANY_PORTS", &self.config.filter.any_ports)?;
        Self::insert_filter_ports(ebpf, "FILTER_SRC_PORTS", &self.config.filter.src_ports)?;
        Self::insert_filter_ports(ebpf, "FILTER_DST_PORTS", &self.config.filter.dst_ports)?;
        Self::insert_filter_ips(ebpf, "FILTER_ANY_IPS", &self.config.filter.any_ips)?;
        Self::insert_filter_ips(ebpf, "FILTER_SRC_IPS", &self.config.filter.src_ips)?;
        Self::insert_filter_ips(ebpf, "FILTER_DST_IPS", &self.config.filter.dst_ips)?;
        Ok(())
    }

    pub async fn stop(self) {
        // Signal child threads to stop
        self.stop_token.cancel();

        if let Some(writer) = self.writer {
            println!("FLUSHING WRITER!");
            let flush_res = writer.shutdown();
            if let Err(res) = flush_res {
                println!("Failed during flush: {}", res);
            } else {
                println!("Flushed successfully!");
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        env_logger::init();

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        let filter_mode = self.config.filter.mode();
        let filter_rules = self.config.filter.rule_flags();
        let mut ebpf = EbpfLoader::new()
            .set_global("FILTER_PORT", &self.config.filter.single_port, true)
            .set_global("FILTER_MODE", &filter_mode, true)
            .set_global("FILTER_RULE_FLAGS", &filter_rules, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/tcbee"
            )))?;
        self.configure_filter(&mut ebpf)?;


        info!("Starting eBPF probes!");

        // TODO: I feel that the dir should be passed to the writer, and the Tracers should just add the filename

        // This is the backend writer thread that reads and writes data to files
        let mut writer = Writer::new();
        let mut watcher_config = self.config.watcher_config();

        // Tracing for packet headers via TC and XDP
        if self.config.headers {
            TCTracer::spawn(
                &mut ebpf,
                self.config.iface.clone(),
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.packets = true;
        }

        // Tracing kernel metrics via FEntry probe
        if self.config.kernel {
            KernelTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;

            watcher_config.graphs.kernel = true;
        }
        // Performance variant of above hook
        if self.config.cwnd {
            CwndTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;

            watcher_config.graphs.kernel = true;
        }

        // Tracing kernel tracepoints
        if self.config.tracepoints {
            TracepointTracer::spawn::<tcp_probe_entry>(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            TracepointTracer::spawn::<tcp_retransmit_synack_entry>(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            TracepointTracer::spawn::<tcp_bad_csum_entry>(
                &mut ebpf,
                self.config.dir.clone(),
                &mut writer,
            )?;

            watcher_config.graphs.tracepoints = true;
        }

        if self.config.algorithms {
            CubicTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer)?;
            watcher_config.graphs.cubic = true;
            if let Err(err) = BBRTracer::spawn(&mut ebpf, self.config.dir.clone(), &mut writer) {
                error!(
                    "Failed to initialize BBR Tracer. Is the kernel module loaded? ({})",
                    err
                );
            };
            watcher_config.graphs.bbr = true;
        }

        // TODO: should be true by default in get_watcher_config()
        watcher_config.graphs.events = true;

        // Start watcher thread
        // Stop token is cloned such that cancellation affects all other threads
        let mut watcher = EBPFWatcher::new(
            &mut ebpf,
            self.config.update_period,
            self.stop_token.clone(),
            watcher_config,
            self.config.do_tui,
        )?;

        self.threads.push(spawn_blocking(move || {
            watcher.run();
        }));

        info!("Finished starting TUI!");

        // Store to ensure that it is not dropped after this function finishes!
        self.ebpf = Some(ebpf);
        self.writer = Some(writer);

        Ok(())
    }
}
