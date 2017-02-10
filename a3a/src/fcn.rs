use std::fmt;
use std::u64;
use std::collections::HashMap;

use bb::BasicBlock;

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

    pub fn calc_metric(&self) {
        for (_, bb) in &self.blocks {
        }
    }

    pub fn dump(&self) {
        println!("Function 0x{:x} bbs: {}", self.entry, self.block_count());
        for (_, bb) in &self.blocks {
            println!("\t{}", bb);
        }
    }
}

