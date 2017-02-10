use std::cmp::Ordering;

pub struct BasicBlock {
    start: u64,
    end: u64,
    jump: u64,
    fail: u64,
}

impl Ord for BasicBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        other.start.cmp(&self.start)
    }
}

impl PartialOrd for BasicBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.start.partial_cmp(&self.start)
    }
}

impl PartialEq for BasicBlock {
    fn eq(&self, other: &Self) -> bool {
        other.start.eq(&self.start)
    }
}

impl Eq for BasicBlock {
}

pub struct BasicBlocks {
    blocks: Vec<BasicBlock>,
}

impl BasicBlocks {
    fn new() -> BasicBlocks {
        BasicBlocks { blocks: Vec::new() }
    }

    fn add(&mut self, start: u64, end: u64, jump: u64, fail: u64) {
        let block = BasicBlock { start: start, end: end, jump: jump, fail: fail };
        self.blocks.push(block);
        self.blocks.sort();
    }

    fn get_crossing_block(&mut self, start: u64, end: u64) {
        println!(" Hallo hallo{:?}", self.blocks.binary_search_by (|probe| probe.start.cmp(&start)));
    }

    fn size(&mut self) -> usize {
        self.blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use BasicBlocks::BasicBlocks;
    #[test]
    fn adding() {
        let mut blocks = BasicBlocks::new();
        blocks.add(1, 2, 10, 20);
        blocks.add(1, 2, 10, 20);
        blocks.add(1, 2, 10, 20);
        assert_eq!(3, blocks.size());
        blocks.get_crossing_block(1,2);
    }
}
