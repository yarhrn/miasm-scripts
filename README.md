# miasm-scripts
Collections of scripts for reverse engineering using miasma

1. graph_waler.py - bfs traversing osf assembler with cycle skipping. (adopted from miasm example - full.py)

```python graph_walker.py fib.out 0x6C0 -l 10 -dst test.asm```