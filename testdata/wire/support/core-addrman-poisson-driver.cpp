// Only the uniform uint64 source is a fixture; distribution and rounding are unmodified Core.
#include <random.h>
#include <bit>
#include <cassert>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <limits>
#include <vector>
struct FixedRand64 : RandomMixin<FixedRand64> {
    uint64_t value{0};unsigned calls{0};
    uint64_t rand64() noexcept {++calls;return value;}
};
int main(){
    const std::vector<uint64_t> samples{0,1,2047,2048,uint64_t{1}<<32,uint64_t{1}<<62,uint64_t{1}<<63,(uint64_t{1}<<63)+(uint64_t{1}<<62),0x123456789abcdef0ULL,0x5555555555555555ULL,0xdeadbeefcafebabeULL,UINT64_MAX-2047,UINT64_MAX};
    std::cout<<std::setprecision(std::numeric_limits<double>::max_digits10);
    for(auto sample:samples){
        FixedRand64 source;source.value=sample;
        const double unscaled=MakeExponentiallyDistributed(sample);
        const auto delay=source.rand_exp_duration(std::chrono::microseconds{120000000});
        assert(source.calls==1);
        std::cout<<"{\"uniform\":"<<sample<<",\"uniform_hex\":\""<<std::hex<<std::setw(16)<<std::setfill('0')<<sample<<std::dec<<"\",\"mean_us\":120000000,\"unscaled\":"<<unscaled<<",\"unscaled_bits_hex\":\""<<std::hex<<std::setw(16)<<std::bit_cast<uint64_t>(unscaled)<<std::dec<<"\",\"delay_us\":"<<delay.count()<<",\"rand64_calls\":"<<source.calls<<"}\n";
    }
}
