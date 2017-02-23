use libc::*;
use std::fmt;
use std::u64;
use std::ffi::CString;
use std::collections::HashMap;

use bb::BasicBlock;
#[link(name="r_cons")]
extern {
    pub fn r_cons_strcat(cstr: *const i8) -> c_void;
}

pub struct Function {
    pub entry: u64,
    pub size: u64,
    pub blocks: HashMap<u64, BasicBlock>,
    pub score: i64,
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "s: 0x{:x}\t blocks: {}\t score:{}", self.entry, self.blocks.len() + 1, self.score)
    }
}

impl Function {
    pub fn new(addr: u64) -> Function {
        Function { entry: addr, size: 0, blocks: HashMap::new(), score: 0 }
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        if block.end < u64::MAX {
            self.score += block.score;
            self.size += block.size();
            self.blocks.entry(block.start).or_insert(block);
        } else {
            //println!("Adding malformed block: {} to {}", block, self);
        }
    }

    pub fn block_count(&self) -> usize {
        return self.blocks.len()
    }

    pub fn contains_block(&self, addr: u64) -> bool {
        self.blocks.contains_key(&addr)
    }

    pub fn get_score(&self) -> i64 {
        self.score
    }

    pub fn dump(&self) {
        unsafe {
            let s : String = format!("af+ 0x{:x} fcn.{:x}\n", self.entry, self.entry);
            r_cons_strcat(CString::new(s).unwrap().as_ptr());
        }
        for (_, bb) in &self.blocks {
            let s: String;
            if bb.jump != u64::MAX {
                if bb.fail != u64::MAX {
                    s = format!("afb+ 0x{:x} 0x{:x} 0x{:x} 0x{:x} 0x{:x}\n",
                        self.entry, bb.start, bb.end - bb.start,
                        bb.jump, bb.fail);
                } else {
                    s = format!("afb+ 0x{:x} 0x{:x} 0x{:x} 0x{:x}\n",
                        self.entry, bb.start, bb.end - bb.start,
                        bb.jump);
                }
            } else {
                 s = format!("afb+ 0x{:x} 0x{:x} 0x{:x}\n", self.entry, bb.start, bb.end - bb.start);
	        }
            unsafe {
                r_cons_strcat(CString::new(s).unwrap().as_ptr());
            }
        }
    }
}

