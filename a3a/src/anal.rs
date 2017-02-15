use std::u64;
use std::io::Write;
use std::io::stderr;
use std::collections::HashMap;

use bb::BlockType;
use bb::BasicBlock;

use fcn::Function;
use metric::Metric;

pub struct Anal {
    pub blocks: Vec<BasicBlock>,
    pub block_map : HashMap<u64, BasicBlock>,
    pub calls: Vec<u64>,
    pub jumps: HashMap<u64, u64>,
    pub functions: Vec<Function>,
}

macro_rules! stderr {
    ($($arg:tt)*) => (
        match writeln!(&mut ::std::io::stderr(), $($arg)* ) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr (file handle closed?): {}", x),
        }
    )
}

impl Anal {
    pub fn new() -> Anal {
        Anal { 
            blocks: Vec::new(),
            block_map: HashMap::new(),
            calls: Vec::new(),
            jumps: HashMap::new(),
            functions: Vec::new(),
        }
    }

    pub fn add(&mut self, start: u64, end: u64, jump: u64, fail: u64, t: BlockType, score: i64) {
        let block = BasicBlock { start: start, end: end, jump: jump, fail: fail, block_type: t, score: score};
        if jump < u64::MAX {
            let jump_bb = BasicBlock { start: jump, end: u64::MAX, jump: u64::MAX, fail: u64::MAX, block_type: t, score: score};
            self.blocks.push(jump_bb);
        }
        self.blocks.push(block);
    }

    pub fn finalize(&mut self) {
        self.blocks.sort();
        let mut result: Vec<BasicBlock> = Vec::new();

        let mut trap_block = false;
        while !self.blocks.is_empty() {
            let mut block = self.blocks.pop().unwrap();
            if block.jump != u64::MAX {
                self.jumps.entry(block.jump).or_insert(block.start);
            }

            if block.fail != u64::MAX {
                self.jumps.entry(block.fail).or_insert(block.start);
            }

            if let Some(last) = self.blocks.last_mut() {
                // check if the next block is the same as this one (multiple inserts)
                if (*last).start == block.start && block.end == u64::MAX {
                    continue;
                }

                match block.block_type {
                    BlockType::Trap => {
                        //merge trap blocks into one block
                        if trap_block == false {
                            trap_block = true;
                            result.push(block);
                            continue;
                        } else {
                            if let Some(last_from_result) = result.last_mut() {
                                (*last_from_result).end += block.end - block.start;
                            } 
                            continue;
                        }
                    }
                    _ => {
                        trap_block = false;
                    }
                }

                if block.start == (*last).start && (*last).end == u64::MAX {
                    (*last).end = block.end;
                    (*last).jump = block.jump;
                    (*last).fail = block.fail;
                    continue;
                }

                // altering two blocks if the (*last) one points with its
                // start address into the block before
                if block.end < u64::MAX && (*last).start < block.end && (*last).start > block.start {
                    if (*last).jump == u64::MAX {
                        (*last).jump = block.jump;
                    }
                    if (*last).fail == u64::MAX {
                        (*last).fail = block.fail;
                    }
                    (*last).end = block.end;
                    block.end = (*last).start;
                    block.jump = (*last).start;
                    block.fail = u64::MAX;
                    (*last).block_type = block.block_type;
                }

            }

            match block.block_type {
                BlockType::Call => {
                    self.calls.push(block.start);
                }
                BlockType::Normal => {
                    result.push(block);
                }

                _ => {}
            }
        }
        for block in &result {
            self.block_map.insert(block.start, *block);
        }
        self.blocks.append(&mut result);
        self.blocks.sort();
        for block in &self.blocks {
            // check if the block is reached by another one
            if !self.jumps.contains_key(&block.start) {
                // go through all basic blocks of the current function
                let mut fcn = Function::new(block.start);
                fcn.add_block(*block);
                let mut offsets: Vec<u64> = Vec::new();
                offsets.push(block.jump);
                offsets.push(block.fail);

                while !offsets.is_empty() {
                    let off = offsets.pop().unwrap();
                    if self.block_map.contains_key(&off) {
                        let current_block = self.block_map.get(&off).unwrap();
                        if !fcn.contains_block(current_block.jump) {
                            offsets.push(current_block.jump);
                        }

                        if !fcn.contains_block(current_block.fail) {
                            offsets.push(current_block.fail);
                        }

                        fcn.add_block(*current_block);
                    }
                }

                if fcn.get_score() == 0 {
                    self.functions.push(fcn);
                }
            }
        }
    }

    pub fn block_count(&mut self) -> usize {
        self.blocks.len()
    }

    pub fn fn_count(&mut self) -> usize {
        self.calls.len()
    }

    pub fn print_info(&mut self) {
        stderr!("{: <10} direct calls", self.calls.len());
        stderr!("{: <10} basic blocks", self.blocks.len());
        stderr!("{: <10} possible functions", self.functions.len());
//        for fcn in &self.functions {
//            let metric = Metric::new(fcn);
//            println!("Metric: {}", metric);
//        }
    }
}

#[cfg(test)]
mod tests {
}
