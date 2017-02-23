#![allow(dead_code)]
extern crate libc;
extern crate rustc_serialize;

use libc::*;
use std::str;
use std::ffi::CStr;
use std::ffi::{CString};
use std::u64;
use rustc_serialize::json;


mod bb;
mod anal;
mod fcn;
use bb::BlockType;

const MY_NAME : *const c_char = b"anal-rs\0" as *const [u8] as *const c_char;
const R2_VERSION: &'static [u8] = b"1.3.0-git\0";
const MY_DESC : &'static [u8] = b"Analysis plugin\0";
const MY_LICENSE : &'static [u8] = b"MIT\0";

// order matters because of libr/util/lib.c
#[repr(C)]
pub enum RLibType {
    RLibTypeIo = 0,
    RLibTypeDbg = 1,
    RLibTypeLang = 2,
    RLibTypeAsm = 3,
    RLibTypeAnal = 4,
    RLibTypeParse = 5,
    RLibTypeBin = 6,
    RLibTypeBinXtr = 7,
    RLibTypeBp = 8,
    RLibTypeSyscall = 9,
    RLibTypeFastcall = 10,
    RLibTypeCrypto = 11,
    RLibTypeCore = 12,
    RLibTypeEgg = 13,
    RLibTypeFs = 14,
    RLibTypeLast = 15,
}

const R_ANAL_OP_TYPE_COND: u64      = 0x80000000;
const R_ANAL_OP_TYPE_REP: u64       = 0x40000000;
const R_ANAL_OP_TYPE_MEM: u64       = 0x20000000; // TODO must be moved to prefix?
const R_ANAL_OP_TYPE_REG: u64       = 0x10000000; // operand is a register
const R_ANAL_OP_TYPE_IND: u64       = 0x08000000; // operand is indirect
const R_ANAL_OP_TYPE_NULL: u64      = 0;
const R_ANAL_OP_TYPE_JMP: u64       = 1;  /* mandatory jump */
const R_ANAL_OP_TYPE_UJMP: u64      = 2;  /* unknown jump (register or so) */
const R_ANAL_OP_TYPE_RJMP: u64      = R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UJMP;
const R_ANAL_OP_TYPE_IJMP: u64		= R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_UJMP;
const R_ANAL_OP_TYPE_IRJMP: u64		= R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UJMP;
const R_ANAL_OP_TYPE_CJMP: u64		= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP;  /* conditional jump */
const R_ANAL_OP_TYPE_MJMP: u64		= R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_JMP;  /* conditional jump */
const R_ANAL_OP_TYPE_UCJMP: u64		= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UJMP; /* conditional unknown jump */
const R_ANAL_OP_TYPE_CALL: u64		= 3;  /* call to subroutine (branch+link) */
const R_ANAL_OP_TYPE_UCALL: u64		= 4; /* unknown call (register or so) */
const R_ANAL_OP_TYPE_RCALL: u64		= R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UCALL;
const R_ANAL_OP_TYPE_ICALL: u64		= R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_UCALL;
const R_ANAL_OP_TYPE_IRCALL: u64	= R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_UCALL;
const R_ANAL_OP_TYPE_CCALL: u64		= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL; /* conditional call to subroutine */
const R_ANAL_OP_TYPE_UCCALL: u64	= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UCALL; /* conditional unknown call */
const R_ANAL_OP_TYPE_RET: u64		= 5; /* returns from subroutine */
const R_ANAL_OP_TYPE_CRET: u64		= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET; /* conditional return from subroutine */
const R_ANAL_OP_TYPE_ILL: u64		= 6;  /* illegal instruction // trap */
const R_ANAL_OP_TYPE_UNK: u64		= 7; /* unknown opcode type */
const R_ANAL_OP_TYPE_NOP: u64		= 8; /* does nothing */
const R_ANAL_OP_TYPE_MOV: u64		= 9; /* register move */
const R_ANAL_OP_TYPE_CMOV: u64		= 9 | R_ANAL_OP_TYPE_COND; /* conditional move */
const R_ANAL_OP_TYPE_TRAP: u64		= 10; /* it's a trap! */
const R_ANAL_OP_TYPE_SWI: u64		= 11;  /* syscall, software interrupt */
const R_ANAL_OP_TYPE_UPUSH: u64		= 12; /* unknown push of data into stack */
const R_ANAL_OP_TYPE_PUSH: u64		= 13;  /* push value into stack */
const R_ANAL_OP_TYPE_POP: u64		= 14;   /* pop value from stack to register */
const R_ANAL_OP_TYPE_CMP: u64		= 15;  /* compare something */
const R_ANAL_OP_TYPE_ACMP: u64		= 16;  /* compare via and */
const R_ANAL_OP_TYPE_ADD: u64		= 17;
const R_ANAL_OP_TYPE_SUB: u64		= 18;
const R_ANAL_OP_TYPE_IO: u64		= 19;
const R_ANAL_OP_TYPE_MUL: u64		= 20;
const R_ANAL_OP_TYPE_DIV: u64		= 21;
const R_ANAL_OP_TYPE_SHR: u64		= 22;
const R_ANAL_OP_TYPE_SHL: u64		= 23;
const R_ANAL_OP_TYPE_SAL: u64		= 24;
const R_ANAL_OP_TYPE_SAR: u64		= 25;
const R_ANAL_OP_TYPE_OR: u64		= 26;
const R_ANAL_OP_TYPE_AND: u64		= 27;
const R_ANAL_OP_TYPE_XOR: u64		= 28;
const R_ANAL_OP_TYPE_NOR: u64		= 29;
const R_ANAL_OP_TYPE_NOT: u64		= 30;
const R_ANAL_OP_TYPE_STORE: u64		= 31;  /* store from register to memory */
const R_ANAL_OP_TYPE_LOAD: u64		= 32;  /* load from memory to register */
const R_ANAL_OP_TYPE_LEA: u64		= 33; /* TODO add ulea */
const R_ANAL_OP_TYPE_LEAVE: u64		= 34;
const R_ANAL_OP_TYPE_ROR: u64		= 35;
const R_ANAL_OP_TYPE_ROL: u64		= 36;
const R_ANAL_OP_TYPE_XCHG: u64		= 37;
const R_ANAL_OP_TYPE_MOD: u64		= 38;
const R_ANAL_OP_TYPE_SWITCH: u64	= 39;
const R_ANAL_OP_TYPE_CASE: u64		= 40;
const R_ANAL_OP_TYPE_LENGTH: u64	= 41;
const R_ANAL_OP_TYPE_CAST: u64		= 42;
const R_ANAL_OP_TYPE_NEW: u64		= 43;
const R_ANAL_OP_TYPE_ABS: u64		= 44;
const R_ANAL_OP_TYPE_CPL: u64		= 45;	/* complement */
const R_ANAL_OP_TYPE_CRYPTO: u64	= 46;
const R_ANAL_OP_TYPE_SYNC: u64		= 47;

#[repr(C)]
pub struct RCorePlugin {
    name: *const c_char,
    desc: *const c_char,
    license: *const c_char,
    pub call: Option<extern "C" fn(*mut c_void, *const c_char) -> c_int>,
    pub init: Option<extern "C" fn(*mut c_void, *const c_char) -> bool>,
    pub deinit: Option<extern "C" fn(*mut c_void, *const c_char) -> bool>,
}


#[repr(C)]
pub struct RListIter {
    data: *mut c_void,
    n: *mut RListIter,
    p: *mut RListIter
}

#[repr(C)]
pub struct RRegItem {
    name: *mut c_char,
    _type: *mut c_int,
    size: *mut c_int, 
    offset: *mut c_int,
    packed_size: *mut c_int,
    is_float: *mut bool,
    flags: *mut c_char,
    index: *mut c_int,
    arena: *mut c_int
}
    
#[repr(C)]
pub struct RList {
    head: *mut RListIter,
    tail: *mut RListIter,
    pub free: Option<extern "C" fn(*mut c_void)>,
    length: *mut c_int,
    sorted: *mut bool
}

#[repr(C)]
pub struct RAnalVar {
    name: *mut c_char,
    _type: *mut c_char,
    kind: c_char,
    addr: u64,
    eaddr: u64,
    size: c_int,
    delta: c_int,
    scope: c_int,
    accesses: *mut RList,
    stores: *mut RList
}

#[repr(C)]
pub struct RAnalValue {
    absolute: c_int,
    memref: c_int,
    base: u64,
    delta: i64,
    imm: i64,
    mul: c_int,
    sel: u16,
    reg: *mut RRegItem,
    regdelta: *mut RRegItem
}

#[repr(C)]
pub struct RStrBuf {
    len: c_int,
    ptr: *mut c_char,
    ptrlen: c_int,
    buf: [c_char ;64]
}

#[repr(C)]
pub struct RAnalSwitchOp {
    addr: u64,
    min_val: u64,
    def_val: u64,
    max_val: u64,
    cases: *mut RList
}

#[repr(C)]
pub struct RAnalOp {
    mnemonic: *mut c_char,
    addr: u64,
    _type: u64,
    prefix: u64,
    type2: u64,
    group: c_int,
    stackop: c_int,
    cond: c_int,
    size: c_int,
    nopcode: c_int,
    cycles: c_int,
    failcycles: c_int,
    family: c_int,
    id: c_int,
    eob: bool,
    delay: c_int,
    jump: u64,
    fail: u64,
    ptr: i64,
    val: u64,
    ptrsize: c_int,
    stackptr: i64,
    refptr: c_int,
    var: *mut RAnalVar,
    src: *mut [RAnalVar; 3],
    dst: *mut RAnalVar,
    next: *mut RAnalOp,
    esil: RStrBuf,
    reg: *const c_char,
    ireg: *const c_char,
    scale: c_int,
    disp: u64,
    switch_op: *mut RAnalSwitchOp
}


#[repr(C)]
pub struct RLibHandler {
    pub _type: c_int,
    pub desc: [c_char; 128], pub user: *const c_void,
    pub constructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
    pub destructor: extern "C" fn(*const RLibPlugin, *mut c_void, *mut c_void),
}

#[repr(C)]
pub struct RLibPlugin {
    pub _type: c_int,
    pub file: *const c_char,
    pub data: *const c_void,
    pub handler: *const RLibHandler,
    pub dl_handler: *const c_void
}

#[repr(C)]
pub struct RLibStruct {
	pub _type: RLibType,
	pub data: *const c_void,
	pub version: *const [u8]
}

// internal radare functions to be defined here
#[link(name="r_cons")]
#[link(name="r_anal")]
#[link(name="r_core")]
extern {
    pub fn r_core_anal_op (core: *mut c_void, addr: u64) -> *mut RAnalOp;
    pub fn r_anal_op_free (op: *mut RAnalOp);
    pub fn r_core_cmd_str (core: *mut c_void, cmd: *const c_char) -> *const c_char;
    pub fn r_core_is_valid_offset (core: *mut c_void, offset: u64) -> c_int;
    pub fn r_core_cmdf (core: *mut c_void, format: *const c_char, ...) -> c_int;
    pub fn r_core_cmd (core: *mut c_void, cstr: *const c_char, log: c_int) -> c_int;
    pub fn r_cons_print(cstr: *const c_char) -> c_void;
}

fn r2_cmd(core: *mut c_void, cmd: &str) -> &str {
    unsafe {
        let s = CString::new(cmd).unwrap();
        let ptr = r_core_cmd_str(core, s.as_ptr());
        let result: &CStr = CStr::from_ptr(ptr);
        match result.to_str() {
            Ok(val) => val,
            Err(_) => "",
        }
    }
}

#[derive(RustcDecodable)]
pub struct Section {
    flags: String,
    name: String,
    paddr: u64,
    size: u64,
    vaddr: u64,
    vsize: u64,
}

fn analyze_binary (core: *mut c_void) -> c_int {
    let mut anal = anal::Anal::new();

    // init sections
    r2_cmd(core, "e anal.afterjmp=false");
    r2_cmd(core, "e anal.vars=false");
    let section_json= r2_cmd(core, "iSj");
    let sections: Vec<Section> = json::decode(section_json).unwrap();

    for section in sections {
        if section.flags.contains("x") {
            let start: u64 = section.vaddr;
            let size: u64 = section.size;

            let mut cur: u64 = 0;
            let mut b_start: u64 = start;
            let mut block_score: i64 = 0;
            while cur < size {
                unsafe {
                    let op: *mut RAnalOp;
                    op = r_core_anal_op (core, start + cur);

                    if op.is_null() {
                        cur += 1;
                        block_score -= 10;
                        continue;
                    } else {
                        match (*op)._type {
                            R_ANAL_OP_TYPE_NOP => {
                            }
                            R_ANAL_OP_TYPE_CALL => {
                                anal.add((*op).jump, std::u64::MAX, std::u64::MAX, std::u64::MAX, BlockType::Call, block_score);
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_RET => {
                                anal.add(b_start, start + cur + (*op).size as u64, std::u64::MAX, std::u64::MAX, BlockType::Normal, block_score);
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_CJMP => {
                                anal.add(b_start, start + cur + (*op).size as u64, (*op).jump, (*op).size as u64 + cur + start, BlockType::Normal, block_score);
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }

                            R_ANAL_OP_TYPE_JMP | R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_RJMP => {
                                anal.add(b_start, start + cur + (*op).size as u64, (*op).jump, std::u64::MAX, BlockType::Normal, block_score);
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_UCALL => {
                                // unknown call (i.e. register)
                                // more investigation to do
                            }
                            R_ANAL_OP_TYPE_TRAP => {
                                if b_start < start + cur {
                                    anal.add(b_start, start + cur , std::u64::MAX, std::u64::MAX, BlockType::Trap, block_score);
                                }
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_UNK => {
                                block_score -= 10;
                            }
                            R_ANAL_OP_TYPE_ILL => {
                                block_score -= 10;
                            }

                            _ => {
                            }
                        }
                        cur += (*op).size as u64;
                        r_anal_op_free (op);
                    }
                }
            }
        }
    }
    anal.finalize();
    for fcn in &anal.functions {
        fcn.dump();
    }
    anal.print_info();
    return 1;
}

extern "C" fn _anal_call (user: *mut c_void, input: *const c_char) -> c_int {
    let c_str: &CStr = unsafe { CStr::from_ptr(input) };
    let bytes = c_str.to_bytes();
    let input = str::from_utf8(bytes).unwrap();
    if input.starts_with("a3a") {
        analyze_binary (user);
        return 1;
    }
    return 0;
}

const R_ANAL_PLUGIN: RCorePlugin = RCorePlugin {
    name : MY_NAME,
    desc : MY_DESC as *const [u8] as *const c_char,
    license : MY_LICENSE as *const [u8] as *const c_char,
    call: Some(_anal_call),
    init: None,
    deinit: None
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    _type : RLibType::RLibTypeCore ,
    data : ((&R_ANAL_PLUGIN) as *const RCorePlugin) as *const c_void,
    version : R2_VERSION
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
