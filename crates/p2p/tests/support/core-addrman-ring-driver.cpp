// Standalone oracle: all placement calls link unmodified Bitcoin Core31.1 sources.
#include <addrman.h>
#include <addrman_impl.h>
#include <netgroup.h>
#include <hash.h>
#include <arpa/inet.h>
#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

std::string Hex(std::span<const unsigned char> data) {
    static constexpr char h[]="0123456789abcdef";
    std::string out;
    for (auto b:data) {out+=h[b>>4];out+=h[b&15];}
    return out;
}
CNetAddr IP(const std::string& text) {
    if(text.rfind("internal:",0)==0) {CNetAddr result; if(!result.SetInternal(text.substr(9))) std::abort();return result;}
    in_addr v4{};
    if(inet_pton(AF_INET,text.c_str(),&v4)==1) return CNetAddr(v4);
    in6_addr v6{};
    if(inet_pton(AF_INET6,text.c_str(),&v6)==1) return CNetAddr(v6);
    std::abort();
}
int main() {
    const auto groups=NetGroupManager::NoAsmap();
    const auto key=(HashWriter{}<<int32_t{1}).GetHash();
    const auto address=IP("8.8.8.8"),source=IP("1.1.1.1");
    std::array<bool,64> found{};
    unsigned remaining=3;
    std::cout<<"secret_raw_hex\taddress\tport\tsource\tnew_bucket\tnew_position\tendpoint_key_hex\n";
    for(unsigned port=1;port<=65535 && remaining;++port) {
        AddrInfo info{CAddress{CService{address,static_cast<uint16_t>(port)},NODE_NONE},source};
        const int bucket=info.GetNewBucket(key,source,groups);
        const int position=info.GetBucketPosition(key,true,bucket);
        if((position==0 || position==1 || position==32) && !found[position]) {
            assert(bucket==191);
            std::cout<<Hex(std::span{key.begin(),key.size()})<<"\t8.8.8.8\t"<<port<<"\t1.1.1.1\t"<<bucket<<'\t'<<position<<'\t'<<Hex(info.GetKey())<<'\n';
            found[position]=true;--remaining;
        }
    }
    return remaining?1:0;
}
