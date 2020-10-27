
#  Egg hunting in Linux x86 Assembly

When writing exploits, you sometimes encounter a situation where your payload is too big, the buffer is to small to fit your payload. This is where "eggs" come in to play. The basic idea of egg hunting is to divide the payload in to two parts, part one is the hunter while part two is the hunted (the egg). The hunter is a set of instructions that searches the program's virtual address space for a given pattern/tag/key (the egg). Once it is found, the hunter will jump to the payload following the key.

The egg can sometimes be referred to as key, tag or pattern. The payload is formatted as `<egg><egg><shellcode>`. The egg is specified twice in order to reduce collisions. If your egg is only four bytes, it could be possible that there exists an instruction that is the same as your egg. Another possibility is that you encounter the egg that you have instructed to look for. Therefore, if you specify the egg twice, you can be sure that is the real egg.

Before continuing this article, I will briefly try to explain a few concepts needed for understanding how egg hunting works. If you already know all about page sizes and virtual address spaces, feel free to skip to **Hunting time**.

### Virtual Address Space

The purpose of an egg hunter is to search for a given egg/tag/key/pattern. The program that searches for this key will search virtual address space (VAS) of a given process. This process is usually the process which your payload gets injected into.

Before I explain what the VAS is, let's look at the memory layout of a linux process. Table 1 visualizes how the memory layout looks like.

| Process Memory layout |
| --------------------- |
| Kernel Space          |
| Stack                 |
| Shared Libs + Mappings|
| Heap                  |
| BSS                   |
| Data                  |
| Text                  |
Table 1: Memory layout of a process

This is how programs are structured. For example, the `Text` segment contains the assembly instructions, the `Data` segment contains initialized global and static variables, and the `BSS` segment contains uninitialized variables.

However, these segments can be spread out when looking at the physical memory address space, meaning the RAM. So how does your operating system know where a segment is and which segments belongs to the correct process? You most likely have multiple programs running at any given time.

This is where the virtual address space comes into play. When you execute a process, your operating system assigns a virtual address space for your process. This not only isolates the process from other running processes, but also tricks the process into thinking that there only exists one space and that the process occupies it. This can be visualised in figure 1:


![vas](vas.png)
Figure 1: Virtual address space vs Physical address space. [1]

The CPU will in turn convert a virtual address to a physical address in order to perform its operations. But wait! There's more :) To make things easier, the virtual and physical address space is further divided into `pages`. More on this in the next section.

### Pages of memory

A page refers to a block of memory of a predefined size. In Linux, it is possible to obtain the page size by running `getconf PAGE_SIZE`. On most x86 Linux systems, the page size is 4096 bytes. Why does this matter for an egg hunter? Well, this information will greatly improve the performance of our search algorithm. Why, you may ask? When allocating memory, the OS will allocate blocks of PAGE_SIZE, which is 4096 bytes. The virtual addresses in each allocated page will be mapped to a physical address. However, there will be virtual addresses that are unmapped, these are invalid addresses. If we can easily skip invalid pages, meaning unmapped blocks of addresses, we can greatly reduce the search time. How this is done is explained in the next section.

## Hunting time

### Final code

## Making the process configurable

## References
[1] [https://commons.wikimedia.org/wiki/File:Virtual_address_space_and_physical_address_space_relationship.svg](https://commons.wikimedia.org/wiki/File:Virtual_address_space_and_physical_address_space_relationship.svg)

