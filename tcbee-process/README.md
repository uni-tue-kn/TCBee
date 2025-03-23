The setup of the eBPF program is really annoying to use in combination with sqlite. (Segfaults on opening a db.....)

This is why the userspace part of the rust eBPF program uses unix sockets to communicate with this db backend!

TODO:
- Remove misalignment flag!
- Add plugin system for other values!