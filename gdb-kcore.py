
proto_families = 'UNSPEC UNIX/LOCAL INET AX25 IPX APPLETALK NETROM BRIDGE ATMPVC X25 INET6 ROSE DECnet NETBEUI SECURITY KEY NETLINK PACKET ASH ECONET ATMSVC RDS SNA IRDA PPPOX WANPIPE LLC IB MPLS CAN TIPC BLUETOOTH IUCV RXRPC ISDN PHONET IEEE802154 CAIF ALG NFC VSOCK KCM QIPCRTR SMC'.split()

def page_address(addr):
    '''Map a struct page to its actuall memory address.
       See __get_free_pages().'''
    return ((((addr + 0x160000000000) >> 6) << 12) + 0xffff888000000000) & ((1 << 64) - 1)

def pcpu_ptr(addr, cpu=0):
    __per_cpu_offset = gdb.parse_and_eval('__per_cpu_offset')
    return addr + int(__per_cpu_offset[cpu])

def possible_cpus():
    possiblemask = gdb.parse_and_eval('__cpu_possible_mask')
    dummy, nbits = possiblemask['bits'].type.range()
    for i in range(nbits):
        bits = int(possiblemask['bits'][i])
        for j in range(64):
            if not (bits & (1 << j)):
                continue
            yield i * 64 + j
            pass
        pass
    pass

__START_KERNEL_map = 0xffffffff80000000
__PAGE_OFFSET_BASE_L5 = 0xff11000000000000
__PAGE_OFFSET_BASE_L4 = 0xffff888000000000
PAGE_OFFSET = __PAGE_OFFSET_BASE_L5
PAGE_SIZE = 4096

phys_base = None

def phys_addr(x):
    global phys_base

    if phys_base is None:
        phys_base = int(gdb.parse_and_eval('phys_base'))
        pass
    y = (x - __START_KERNEL_map) & 0xffffffffffffffff
    if x > y:
        x = y + phys_base
    else:
        x = y + (__START_KERNEL_map - PAGE_OFFSET)
        pass
    return x & 0xffffffffffffffff

class PhysAddr(gdb.Command):
    '''Translate a virtual address to its physical address'''
    def __init__(self):
        super(PhysAddr, self).__init__('kern-phys-addr', gdb.COMMAND_USER)
        pass

    def invoke(self, arg, from_tty):
        vaddr = int(gdb.parse_and_eval(arg))
        paddr = phys_addr(vaddr)
        print('0x%x' % paddr)
        pass
    pass

class CollectKmemCache:
    def __init__(self, cachename, objtype):
        self.cachename = cachename
        self.objtype = objtype
        self.result = []
        pass

    @staticmethod
    def listhead_to_page(h):
        slab_list_off = int(gdb.parse_and_eval('&((struct page *)0)->slab_list'))
        haddr = int(h)
        paddr = haddr - slab_list_off
        pg = gdb.Value(paddr).cast(gdb.lookup_type('struct page').pointer())
        return pg

    def show_obj(self, objp):
        self.result.append(objp)
        pass

    def list_page(self, pg, cache):
        paddr = page_address(int(pg))
        paddr += int(cache['red_left_pad'])
        otp = gdb.lookup_type(self.objtype).pointer()
        osz = int(cache['size'])
        for i in range(int(pg['objects'])):
            objp = gdb.Value(paddr).cast(otp)
            self.show_obj(objp)
            paddr += osz
            pass
        pass

    def collect_pages(self, hfirst, cache):
        h = hfirst['next']
        pages = []
        while int(h) and int(h) != int(hfirst.address) and (int(h) & 0xffff000000000000) != 0xdead000000000000:
            pg = self.listhead_to_page(h)
            try:
                h = h['next']
            except gdb.MemoryError:
                print('memory error')
                raise
            pages.append(pg)
            pass
        return pages

    def show_pages(self, pages, cache):
        for pg in pages:
            try:
                self.list_page(pg, cache)
            except gdb.MemoryError:
                print('memory error: list_page')
                raise
            pass
        pass

    def collect_cache_node(self, n, cache):
        n = n.dereference()
        pages = self.collect_pages(n['full'], cache)
        pages.extend(self.collect_pages(n['partial'], cache))
        return pages

    def pre_list(self, cache):
        pass

    def list_all(self, cache):
        self.count = 0
        self.pre_list(cache)

        node = cache['node']
        slab_nodes_bits = int(gdb.parse_and_eval('slab_nodes.bits[0]'))
        i = 0
        pages = []
        while slab_nodes_bits:
            if not (slab_nodes_bits & (0x1 << i)):
                continue
            slab_nodes_bits &= ~(0x1 << i)
            n = node[i]
            pages.extend(self.collect_cache_node(n, cache))
            i += 1
            pass

        cpus = int(gdb.parse_and_eval('__num_online_cpus.counter'))
        for cpu in range(cpus):
            cpu_slab_addr = pcpu_ptr(int(cache['cpu_slab']), cpu)
            cpu_slab = gdb.Value(cpu_slab_addr).cast(gdb.lookup_type('struct kmem_cache_cpu').pointer())
            pg = cpu_slab.dereference()['page']
            if int(pg):
                pages.append(pg)
                pass
            pass

        self.show_pages(pages, cache)
        pass

    def collect(self):
        files_cachep = gdb.parse_and_eval(self.cachename)
        self.list_all(files_cachep)
        return self.result
    pass

class ListKmemCache(gdb.Command):
    def __init__(self, cmd, cachename, objtype):
        super(ListKmemCache, self).__init__(cmd, gdb.COMMAND_USER)
        self.cmd = cmd
        self.cachename = cachename
        self.objtype = objtype
        pass

    @staticmethod
    def listhead_to_page(h):
        slab_list_off = int(gdb.parse_and_eval('&((struct page *)0)->slab_list'))
        haddr = int(h)
        paddr = haddr - slab_list_off
        pg = gdb.Value(paddr).cast(gdb.lookup_type('struct page').pointer())
        return pg

    def show_obj(self, objp):
        obj = objp.dereference()
        print('(%s)%s %s\n' % (objp.type, objp, obj))
        self.count += 1
        pass

    def list_page(self, pg, cache):
        paddr = page_address(int(pg))
        paddr += int(cache['red_left_pad'])
        otp = gdb.lookup_type(self.objtype).pointer()
        osz = int(cache['size'])
        for i in range(int(pg['objects'])):
            objp = gdb.Value(paddr).cast(otp)
            self.show_obj(objp)
            paddr += osz
            pass
        pass

    def collect_pages(self, hfirst, cache):
        h = hfirst['next']
        pages = []
        while int(h) and int(h) != int(hfirst.address) and (int(h) & 0xffff000000000000) != 0xdead000000000000:
            pg = self.listhead_to_page(h)
            try:
                h = h['next']
            except gdb.MemoryError:
                print('memory error')
                raise
            pages.append(pg)
            pass
        return pages

    def show_pages(self, pages, cache):
        for pg in pages:
            print(':page', pg)
            try:
                self.list_page(pg, cache)
            except gdb.MemoryError:
                print('memory error: list_page')
                raise
            pass
        pass

    def collect_cache_node(self, n, cache):
        n = n.dereference()
        pages = self.collect_pages(n['full'], cache)
        pages.extend(self.collect_pages(n['partial'], cache))
        return pages

    def pre_list(self, cache):
        pass

    def list_all(self, cache):
        self.count = 0
        self.pre_list(cache)

        node = cache['node']
        slab_nodes_bits = int(gdb.parse_and_eval('slab_nodes.bits[0]'))
        i = 0
        pages = []
        while slab_nodes_bits:
            if not (slab_nodes_bits & (0x1 << i)):
                continue
            slab_nodes_bits &= ~(0x1 << i)
            n = node[i]
            pages.extend(self.collect_cache_node(n, cache))
            i += 1
            pass

        cpus = int(gdb.parse_and_eval('__num_online_cpus.counter'))
        for cpu in range(cpus):
            cpu_slab_addr = pcpu_ptr(int(cache['cpu_slab']), cpu)
            cpu_slab = gdb.Value(cpu_slab_addr).cast(gdb.lookup_type('struct kmem_cache_cpu').pointer())
            pg = cpu_slab.dereference()['page']
            if int(pg):
                pages.append(pg)
                pass
            pass

        self.show_pages(pages, cache)
        print('Total:', self.count)
        pass

    def invoke(self, arg, from_tty):
        files_cachep = gdb.parse_and_eval(self.cachename)
        self.list_all(files_cachep)
        return
    pass

class ListKFiles(ListKmemCache):
    '''List all file_struct object from files_cachep, a kmem_cache'''
    def __init__(self):
        super(ListKFiles, self).__init__('list-kern-files', 'files_cachep', 'struct files_struct')
        pass
    pass

class ListKFileObjs(ListKmemCache):
    '''List all file objects from filp_cachep, a kmem_cache'''
    def __init__(self):
        super(ListKFileObjs, self).__init__('list-kern-file-objs', 'filp_cachep', 'struct file')
        pass
    pass

class ListKINodes(ListKmemCache):
    '''List all inodes from inode_cachep, a kmem_cache'''
    def __init__(self):
        super(ListKINodes, self).__init__('list-kern-inodes', 'inode_cachep', 'struct inode')
        pass
    pass

class ListKNetNS(ListKmemCache):
    '''List all net namespace found from net_cachep, a kmem_cache'''
    def __init__(self):
        super(ListKNetNS, self).__init__('list-kern-netns', 'net_cachep', 'struct net')
        pass

    def show_obj(self, objp):
        obj = objp.dereference()
        passive = int(obj['passive']['refs']['counter'])
        if passive < 0 or passive > 100:
            return
        loopback_dev = obj['loopback_dev']
        if int(loopback_dev) == 0:
            return
        inum = obj['ns']['inum']
        if inum == 0:
            return
        print('(%s)%s inum %s' % (objp.type, objp, inum))
        print(obj)
        self.count += 1
        pass

    def pre_list(self, cache):
        init_net = gdb.parse_and_eval('&init_net')
        print(':init_net')
        self.show_obj(init_net)
        pass
    pass

class ListKSockAllocs(ListKmemCache):
    '''Explore all objects in a kmem_cache'''
    def __init__(self):
        super(ListKSockAllocs, self).__init__('list-kern-sockallocs', 'sock_inode_cachep', 'struct socket_alloc')
        pass

    def show_obj(self, objp):
        obj = objp.dereference()
        try:
            family = proto_families[int(obj['socket']['ops'].dereference()['family'])]
        except:
            family = 'INVALID'
            pass
        print('(%s)%s %s' % (objp.type, objp, family))
        print(obj)
        self.count += 1
        pass
    pass

class ListKSockNS(ListKmemCache):
    '''List all sockets found in sock_inode_cache the kmem_cache where sockets are allocated'''
    def __init__(self):
        super(ListKSockNS, self).__init__('list-kern-sock-ns', 'sock_inode_cachep', 'struct socket_alloc')
        pass

    def show_obj(self, objp):
        obj = objp.dereference()
        try:
            family = proto_families[int(obj['socket']['ops'].dereference()['family'])]
        except:
            family = 'INVALID'
            pass

        sk = obj['socket']['sk']
        if not int(sk):
            return

        try:
            netns = sk.dereference()['__sk_common']['skc_net']['net']
        except gdb.MemoryError:
            print('memory error: fail to get struct net')
            return

        inum = int(netns['ns']['inum'])
        if inum != 4026533578 and False:
            return

        print('(%s)%s %s' % (objp.type, objp, family))
        print('    netns (%s)%s inum %d' % (netns.type, netns, inum))
        self.count += 1
        pass
    pass

class ContainerOf(gdb.Command):
    '''args: ptr, container_type, container_member'''
    def __init__(self):
        super(ContainerOf, self).__init__('container_of', gdb.COMMAND_USER)
        pass

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 3:
            print('incorrect argument number:', len(args))
            pass
        ptr, type, member = tuple(args)
        off = gdb.parse_and_eval('(unsigned long)&((struct %s *)0)->%s' % (type, member))
        addr = int(gdb.parse_and_eval(ptr))
        cntnr = gdb.Value(addr - off).cast(gdb.lookup_type('struct ' + type).pointer())
        print('(%s)%s' % (cntnr.type, cntnr))
        pass
    pass

class ListKList(gdb.Command):
    def __init__(self):
        super(ListKList, self).__init__('list-kern-list', gdb.COMMAND_USER)
        pass

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 3:
            print('incorrect argument number:', len(args))
            pass
        head, type, member = tuple(args)
        off = gdb.parse_and_eval('(unsigned long)&((struct %s *)0)->%s' % (type, member))
        head = gdb.parse_and_eval(head)
        cur = head.dereference()['next']
        while int(cur) and int(cur) != int(head):
            addr = int(cur)
            cntnr = gdb.Value(addr - off).cast(gdb.lookup_type('struct ' + type).pointer())
            print('(%s)%s %s' % (cntnr.type, cntnr, cntnr.dereference()))
            cur = cur.dereference()['next']
            pass
        pass
    pass

class radix_tree:
    CONFIG_BASE_SMALL = 0
    if CONFIG_BASE_SMALL:
        MAP_SIZE = 1 << 4
    else:
        MAP_SIZE = 1 << 6
        pass
    MAP_MASK = MAP_SIZE - 1

    RETRY = (256 << 2) | 2

    @staticmethod
    def node_maxindex(node):
        shift = int(node.dereference()['shift'])
        return (radix_tree.MAP_SIZE << shift) - 1

    @staticmethod
    def is_internal_node(node):
        return (int(node) & 0x3) == 0x2

    @staticmethod
    def entry_to_node(node):
        return gdb.Value(int(node) & ~0x2).cast(node.type)

    @staticmethod
    def load_root(root):
        xa_head = root.dereference()['xa_head']
        node = xa_head.cast(gdb.lookup_type('struct xa_node').pointer())
        if radix_tree.is_internal_node(node):
            return node
        return None

    @staticmethod
    def descend(parent, index):
        p = parent.dereference()
        offset = (index >> int(p['shift'])) & radix_tree.MAP_MASK
        entry = p['slots'][offset]
        return entry.cast(parent.type), offset

    @staticmethod
    def next_chunk(iter):
        index = iter.next_index
        if index == 0 and iter.index != 0:
            return
        restart = True
        while restart:
            restart = False
            child = radix_tree.load_root(iter.root)
            if not child:
                return
            child_n = radix_tree.entry_to_node(child)
            maxindex = radix_tree.node_maxindex(child_n)
            if index > maxindex:
                return
            if not radix_tree.is_internal_node(child):
                iter.index = index
                iter.next_index = maxindex + 1
                iter.tags = 1
                iter.node = None
                return child

            while True:
                node = radix_tree.entry_to_node(child)
                child, offset = radix_tree.descend(node, index)
                if not child:
                    offset += 1
                    while offset < radix_tree.MAP_SIZE:
                        slot = node.dereference()['slots'][offset]
                        if int(slot):
                            break
                        offset += 1
                        pass

                    index &= ~radix_tree.node_maxindex(node)
                    index += offset << int(node.dereference()['shift'])
                    index &= (1 << 64) - 1
                    if not index:
                        return
                    if offset == radix_tree.MAP_SIZE:
                        restart = True
                        break
                    child = node.dereference()['slots'][offset].cast(child.type)
                    pass
                if int(child) == radix_tree.RETRY:
                    break
                if (not node.dereference()['shift']) or (not radix_tree.is_internal_node(child)):
                    break
                pass
            pass

        iter.index = (index & ~radix_tree.node_maxindex(node)) | offset
        iter.next_index = (index | radix_tree.node_maxindex(node)) + 1
        iter.node = node

        return node.dereference()['slots'][offset].address

    @staticmethod
    def chunk_size(iter):
        return iter.next_index - iter.index

    @staticmethod
    def next_slot(iter):
        slot = iter.slot
        count = radix_tree.chunk_size(iter)

        count -= 1
        while count > 0:
            slot = gdb.Value(int(slot) + slot.dereference().type.sizeof).cast(slot.type)
            iter.index += 1

            if int(slot.dereference()):
                return slot
            count -= 1
            pass
        pass
    pass

class radix_tree_iter:
    def __init__(self, root, start = 0):
        self.root = root
        self.index = 0
        self.next_index = start
        self.tags = 0
        self.node = None
        self.slot = None
        pass

    def __iter__(self):
        return self

    def __next__(self):
        if not self.slot:
            slot = radix_tree.next_chunk(self)
        else:
            slot = radix_tree.next_slot(self)
            if not slot:
                slot = radix_tree.next_chunk(self)
                pass
            pass

        if not slot:
            raise StopIteration
        self.slot = slot

        return radix_tree.entry_to_node(slot.dereference())
    pass

class ListRadixTree(gdb.Command):
    def __init__(self, cmd, idrname, objtype):
        super(ListRadixTree, self).__init__(cmd, gdb.COMMAND_USER)
        self.idrname = idrname
        self.objtype = objtype
        pass

    def show_obj(self, obj):
        print('(%s)%s %s\n' % (obj.type, obj, obj.dereference()))
        pass

    def invoke(self, arg, from_tty):
        idr = gdb.parse_and_eval(self.idrname)
        root = idr['idr_rt'].address
        rt_iter = radix_tree_iter(root)
        otp = gdb.lookup_type(self.objtype).pointer()
        objs = [obj.cast(otp) for obj in rt_iter]
        for obj in objs:
            self.show_obj(obj)
            pass
        print('Total:', len(objs))
        pass
    pass

class ListKBPFProgs(ListRadixTree):
    '''List all bpf progs'''
    def __init__(self):
        super(ListKBPFProgs, self).__init__('list-kern-bpf-progs', 'prog_idr', 'struct bpf_prog')
        pass

    def show_obj(self, obj):
        name = obj.dereference()['aux'].dereference()['name']
        print('(%s)%s name %s %s\n' % (obj.type, obj, name, obj.dereference()))
        pass
    pass

class ListKBPFMaps(ListRadixTree):
    '''List all bpf maps'''
    def __init__(self):
        super(ListKBPFMaps, self).__init__('list-kern-bpf-maps', 'map_idr', 'struct bpf_map')
        pass
    pass

class fib6_table_iter:
    def __init__(self, tab):
        self.tab = tab
        self.node = tab.dereference()['tb6_root'].address
        self.depth = 0
        pass

    def __iter__(self):
        return self

    def __next__(self):
        node = self.node
        if not node:
            raise StopIteration

        depth = self.depth
        node_v = node.dereference()
        next_node = node_v['subtree']
        if not int(next_node):
            next_node = node_v['left']
            pass
        if not int(next_node):
            next_node = node_v['right']
            pass
        if int(next_node):
            self.node = next_node
            self.depth += 1
            return node, depth

        parent = node_v['parent']
        while int(parent):
            parent_v = parent.dereference()
            if int(parent_v['right']) == int(node):
                node = parent
                depth -= 1
                parent = node.dereference()['parent']
                continue
            if int(parent_v['left']) == int(node):
                node = parent['right']
                self.node = node
                self.depth = depth
                return node, depth
            if int(parent_v['subtree']) == int(node):
                node = parent['left']
                self.node = node
                self.depth = depth
                return node, depth
            print(node_v)
            raise ValueError

        self.node = None
        self.depth = -1
        return node, depth
    pass

class link_list_iter:
    def __init__(self, head, tp, member, include_first=False, first='next'):
        self.head = head
        if include_first:
            self.node = head
        else:
            self.node = head.dereference()[first]
            pass
        self.tp = tp
        self.member = member
        self.off = int(gdb.parse_and_eval('&((%s *)0)->%s' % (tp, member)))
        pass

    def __iter__(self):
        return self

    def __next__(self):
        if not int(self.node):
            raise StopIteration
        if int(self.node) == int(self.head):
            raise StopIteration

        node = self.node
        node_v = node.dereference()
        next_node = node_v['next']
        self.node = next_node

        return gdb.Value(int(node) - self.off) \
                       .cast(gdb.lookup_type(self.tp).pointer())
    pass

class ListList(gdb.Command):
    def __init__(self, cmd, head, tp, member):
        super(ListList, self).__init__(cmd, gdb.COMMAND_USER)
        self.head = gdb.parse_and_eval(head)
        self.tp = tp
        self.member = member
        pass

    def show_obj(self, obj):
        print('(%s)%s %s\n' % (obj.type, obj, obj.dereference()))
        pass

    def invoke(self, arg, from_ttye):
        objs = [obj for obj in link_list_iter(self.head, self.tp, self.member)]
        for obj in objs:
            self.show_obj(obj)
            pass
        print('Total:', len(objs))
        pass
    pass

class ListKNetNSList(ListList):
    '''List all net namespaces from net_namespace_list'''
    def __init__(self):
        super(ListKNetNSList, self).__init__('list-kern-netns-list', '&net_namespace_list', 'struct net', 'list')
        pass
    pass

class ListFib6Table(gdb.Command):
    '''List fib6_tables of a given net namespace'''
    def __init__(self):
        super(ListFib6Table, self).__init__('list-kern-fib6-table', gdb.COMMAND_USER)
        pass

    def show_node(self, node, depth):
        node_v = node.dereference()
        print(depth, node, node_v)
        rt = node_v['leaf']
        rt_v = rt.dereference()
        print('  leaf %s %s' % (rt, rt_v))
        if int(rt_v['fib6_nsiblings']):
            for sibling in link_list_iter(rt_v['fib6_siblings'], 'struct fib6_info', 'fib6_siblings'):
                print('  sibling %s' % sibling.dereference())
                pass
        elif int(rt_v['nh']):
            print('  nh %s' % rt_v['nh'].dereference())
        else:
            print('  fib6_nh %s %s' % (rt_v['fib6_nh'][0].address, rt_v['fib6_nh'][0]))
            dev = rt_v['fib6_nh']['nh_common']['nhc_dev']
            if int(dev):
                print('    dev %s' % dev.dereference()['name'])
                pass
            pass
        pass

    def invoke(self, arg, from_tty):
        net = gdb.parse_and_eval(arg[0])
        if not int(net):
            print('The first argument should be a struct net')
            return
        fib6_null_entry = net.dereference()['ipv6']['fib6_null_entry']
        if int(fib6_null_entry):
            print('fib6_null_entry %s %s' % (fib6_null_entry, fib6_null_entry.dereference()))
            pass
        ip6_null_entry = net.dereference()['ipv6']['ip6_null_entry']
        if int(ip6_null_entry):
            print('ip6_null_entry %s %s' % (ip6_null_entry, ip6_null_entry.dereference()))
            pass
        ftb = net.dereference()['ipv6']['fib_table_hash']
        for i in range(0, 256):
            for tb in link_list_iter(ftb[i].address, 'struct fib6_table', 'tb6_hlist', first='first'):
                tb_v = tb.dereference()
                print(':table %s' % (tb_v['tb6_id']))
                for node, depth in fib6_table_iter(tb):
                    self.show_node(node, depth)
                    pass
                pass
            pass
        pass
    pass

class ListNSFib6Table(gdb.Command):
    '''List all fib6_tables of every net namespace'''
    def __init__(self):
        super(ListNSFib6Table, self).__init__('list-kern-ns-fib6-table', gdb.COMMAND_USER)
        pass

    def show_node(self, node, depth):
        node_v = node.dereference()
        print(depth, node, node_v)
        rt = node_v['leaf']
        rt_v = rt.dereference()
        print('  leaf %s %s' % (rt, rt_v))
        if int(rt_v['fib6_nsiblings']):
            for sibling in link_list_iter(rt_v['fib6_siblings'], 'struct fib6_info', 'fib6_siblings'):
                print('  sibling %s' % sibling.dereference())
                pass
        elif int(rt_v['nh']):
            print('  nh %s' % rt_v['nh'].dereference())
        else:
            print('  fib6_nh %s %s' % (rt_v['fib6_nh'][0].address, rt_v['fib6_nh'][0]))
            dev = rt_v['fib6_nh']['nh_common']['nhc_dev']
            if int(dev):
                print('    dev %s' % dev.dereference()['name'])
                pass
            pass
        pass

    def show_ns(self, net):
        fib6_null_entry = net.dereference()['ipv6']['fib6_null_entry']
        if int(fib6_null_entry):
            print('fib6_null_entry %s' % fib6_null_entry)
            pass
        ip6_null_entry = net.dereference()['ipv6']['ip6_null_entry']
        if int(ip6_null_entry):
            print('ip6_null_entry %s %s' % (ip6_null_entry, ip6_null_entry.dereference()))
            pass
        ftb = net.dereference()['ipv6']['fib_table_hash']
        for i in range(0, 256):
            for tb in link_list_iter(ftb[i].address, 'struct fib6_table', 'tb6_hlist', first='first'):
                tb_v = tb.dereference()
                try:
                    print(':table %s' % (tb_v['tb6_id']))
                except gdb.MemoryError:
                    print('memory error: fail to read a fib6_table', tb)
                    continue
                for node, depth in fib6_table_iter(tb):
                    try:
                        self.show_node(node, depth)
                    except gdb.MemoryError:
                        print('memory error: fail to show a node')
                        break
                    pass
                pass
            pass
        pass

    def invoke(self, arg, from_tty):
        init_net = gdb.parse_and_eval('&init_net')
        all_netns = [init_net] + CollectKmemCache('net_cachep', 'struct net').collect()
        for netns in all_netns:
            print(':netns %s' % netns)
            try:
                self.show_ns(netns)
            except gdb.MemoryError:
                print('memory error: fail to show a nets')
                pass
            pass
        pass
    pass

class PCPURefCount(gdb.Command):
    '''Read a per cpu refcnt (ptr)'''
    def __init__(self, cmd='read-pcpu-refcnt'):
        super(PCPURefCount, self).__init__(cmd, gdb.COMMAND_USER)
        pass

    def compute(self, refcnt):
        total = 0
        for cpu in possible_cpus():
            addr = pcpu_ptr(int(refcnt), cpu)
            cpucnt = gdb.Value(addr).cast(refcnt.type)
            total += int(cpucnt.dereference())
            pass
        total &= 0xffffffff
        return total

    def invoke(self, arg, from_tty):
        refcnt = gdb.parse_and_eval(arg)
        total = self.compute(refcnt)
        print(total)
        pass
    pass

class NetdevPCPURefCount(PCPURefCount):
    '''Read the refcnt of a net_device (ptr)'''
    def __init__(self):
        super(NetdevPCPURefCount, self).__init__('read-netdev-refcnt')
        pass

    def invoke(self, arg, from_tty):
        dev = gdb.parse_and_eval(arg)
        refcnt = dev.dereference()['pcpu_refcnt']
        total = self.compute(refcnt)
        print(total)
        pass
    pass

PhysAddr()
ListKFiles()
ListKFileObjs()
ListKINodes()
ListKNetNS()
ListKSockAllocs()
ListKSockNS()
ContainerOf()
ListKList()
ListKBPFProgs()
ListKBPFMaps()
ListFib6Table()
ListNSFib6Table()
ListKNetNSList()
PCPURefCount()
NetdevPCPURefCount()
