"""Run one function of a UniFi MIPS16e libubnt.so under Unicorn, as a black-box oracle.

Built for U7LR 6.8.2 (BZ2/QCA956x, plaintext): `calc_sta_satisfaction` at 0x21501.
Soft-float libgcc imports (the GOT entries of undefined symbols) are trapped and
emulated; libubnt_log is a no-op. Addresses must stay below 0x80000000 (kseg2 is
TLB-mapped in Unicorn). Offsets are hard-coded for that build: SYMTAB, GP, PLTGOT,
LOCAL_GOTNO, GOTSYM, the data segment's file offset. Re-derive them with
`mips-linux-gnu-readelf -dW` for another build.
Usage: LIBUBNT=path python3 -c "from oracle import *; print(Oracle().run({376:('>I',1000)}))"
"""
import struct, math
from unicorn import *
from unicorn.mips_const import *
import os
d=open(os.environ.get('LIBUBNT','libubnt.so.1.0.0'),'rb').read()
SYMTAB=0x1778; GP=0xF9600; PLTGOT=0xf1610; LOCAL=23; GOTSYM=0x12f; NSYM=821
dyn=d[0x130:0x130+0x148]; tags={}
for i in range(0,len(dyn),8):
    t,v=struct.unpack('>II',dyn[i:i+8]); tags.setdefault(t,v)
STR=tags[5]
def sym(i):
    n,val,size,info,other,shndx=struct.unpack('>IIIBBH',d[SYMTAB+16*i:SYMTAB+16*i+16])
    e=d.index(b'\0',STR+n); return d[STR+n:e].decode(),val,shndx
TRAP=0x60000000
STRUCT=0x70000000; STACK=0x7F000000; SENT=0x600F0000
def f32(b): return struct.unpack('>f',struct.pack('>I',b&0xffffffff))[0]
def b32(x): return struct.unpack('>I',struct.pack('>f',x))[0]
def f64(hi,lo): return struct.unpack('>d',struct.pack('>II',hi&0xffffffff,lo&0xffffffff))[0]
def b64(x): return struct.unpack('>II',struct.pack('>d',x))
def s32(x): x&=0xffffffff; return x-(1<<32) if x>>31 else x
def trunc(x):
    if x!=x: return 0
    return max(-2**31,min(2**31-1,int(x)))
class Oracle:
    def __init__(self):
        self.mu=mu=Uc(UC_ARCH_MIPS, UC_MODE_MIPS32|UC_MODE_BIG_ENDIAN)
        mu.mem_map(0,0x120000); mu.mem_map(TRAP,0x200000)
        mu.mem_map(STRUCT,0x10000); mu.mem_map(STACK-0x20000,0x30000)
        mu.mem_write(0,d[:0x39218]); mu.mem_write(0x49824,d[0x39824:0x39824+0xa8664])
        self.names={}
        for k in range(NSYM-GOTSYM):
            idx=LOCAL+k; name,val,shndx=sym(GOTSYM+k)
            if shndx==0:
                a=TRAP+0x10*k; self.names[a]=name
                mu.mem_write(PLTGOT+4*idx,struct.pack('>I',a|1))
        mu.hook_add(UC_HOOK_CODE,self.hook,begin=TRAP,end=TRAP+0x200000)
        self.snap=bytes(mu.mem_read(0,0x120000))
    def hook(self,mu,addr,size,ud):
        if addr==SENT: mu.emu_stop(); return
        name=self.names.get(addr)
        r=lambda n: mu.reg_read(n)
        a0,a1,a2,a3=[r(x) for x in (UC_MIPS_REG_A0,UC_MIPS_REG_A1,UC_MIPS_REG_A2,UC_MIPS_REG_A3)]
        v0=v1=0
        if name is None: raise Exception('trap at %x'%addr)
        if name=='__floatunsisf': v0=b32(float(a0&0xffffffff))
        elif name=='__floatsisf': v0=b32(float(s32(a0)))
        elif name=='__fixsfsi': v0=trunc(f32(a0))&0xffffffff
        elif name=='__extendsfdf2': v0,v1=b64(f32(a0))
        elif name=='__divdf3': v0,v1=b64(f64(a0,a1)/f64(a2,a3))
        elif name=='__muldf3': v0,v1=b64(f64(a0,a1)*f64(a2,a3))
        elif name=='__subdf3': v0,v1=b64(f64(a0,a1)-f64(a2,a3))
        elif name=='__fixdfsi': v0=trunc(f64(a0,a1))&0xffffffff
        elif name=='__floatundisf': v0=b32(float(((a0&0xffffffff)<<32)|(a1&0xffffffff)))
        elif name=='__divsf3': v0=b32(f32(a0)/f32(a1) if f32(a1)!=0 else math.inf)
        elif name=='__mulsf3': v0=b32(f32(a0)*f32(a1))
        elif name=='__subsf3': v0=b32(f32(a0)-f32(a1))
        elif name=='__addsf3': v0=b32(f32(a0)+f32(a1))
        elif name=='__gesf2': x,y=f32(a0),f32(a1); v0=(1 if x>y else 0 if x==y else (-1 if x<y else -1))&0xffffffff
        elif name=='__gtsf2': x,y=f32(a0),f32(a1); v0=(1 if x>y else 0 if x==y else -1 if x<y else -1)&0xffffffff
        elif name=='__ltsf2': x,y=f32(a0),f32(a1); v0=(-1 if x<y else 0 if x==y else 1)&0xffffffff
        elif name=='__lesf2': x,y=f32(a0),f32(a1); v0=(-1 if x<y else 0 if x==y else 1)&0xffffffff
        elif name=='libubnt_log': v0=0
        else: raise Exception('unhandled import '+name)
        mu.reg_write(UC_MIPS_REG_V0,v0&0xffffffff); mu.reg_write(UC_MIPS_REG_V1,v1&0xffffffff)
        mu.reg_write(UC_MIPS_REG_PC,r(UC_MIPS_REG_RA))
    def run(self,fields,func=0x21501,args=None,size=0x800,table=None):
        mu=self.mu
        mu.mem_write(0,self.snap[:0x120000]) if False else None
        mu.mem_write(STRUCT,b'\0'*size)
        for off,(fmt,val) in fields.items(): mu.mem_write(STRUCT+off,struct.pack(fmt,val))
        mu.reg_write(UC_MIPS_REG_SP,STACK); mu.reg_write(UC_MIPS_REG_RA,SENT|1)
        mu.reg_write(UC_MIPS_REG_A0,STRUCT)
        mu.reg_write(UC_MIPS_REG_T9,func)
        try:
            mu.emu_start(func,SENT,timeout=2000000,count=200000)
        except UcError as e:
            print('UcError',e,'pc=%x'%mu.reg_read(UC_MIPS_REG_PC),'ra=%x'%mu.reg_read(UC_MIPS_REG_RA),'gp=%x'%mu.reg_read(UC_MIPS_REG_GP),'v0=%x v1=%x a0=%x s0=%x s1=%x'%tuple(mu.reg_read(x) for x in (UC_MIPS_REG_V0,UC_MIPS_REG_V1,UC_MIPS_REG_A0,UC_MIPS_REG_S0,UC_MIPS_REG_S1)))
            raise
        return mu.reg_read(UC_MIPS_REG_V0), bytes(mu.mem_read(STRUCT,size))
