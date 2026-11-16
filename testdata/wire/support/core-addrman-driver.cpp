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
    std::array<unsigned char,32> ramp{};
    for(unsigned i=0;i<ramp.size();++i) ramp[i]=i;
    std::vector<std::pair<std::string,uint256>> keys{
        {"hash-int32-1",(HashWriter{}<<int32_t{1}).GetHash()},
        {"hash-int32-2",(HashWriter{}<<int32_t{2}).GetHash()},
        {"ramp-00-1f",uint256{ramp}},
        {"zero",uint256{}},
    };
    AddrInfo official_tried{CAddress{CService{IP("250.1.1.1"),8333},NODE_NONE},IP("250.1.1.1")};
    AddrInfo official_new{CAddress{CService{IP("250.1.2.1"),8333},NODE_NONE},IP("250.1.2.1")};
    if(official_tried.GetTriedBucket(keys[0].second,groups)!=40 || official_new.GetNewBucket(keys[0].second,groups)!=786) return 2;
    struct Row {const char* address;uint16_t port;const char* source;};
    const std::vector<Row> rows{
        {"250.1.1.1",8333,"250.1.1.1"},{"250.1.2.1",8333,"250.1.2.1"},
        {"8.8.8.8",8333,"1.1.1.1"},{"8.8.8.8",9999,"1.1.1.1"},
        {"8.8.9.1",8333,"1.1.9.9"},{"8.9.8.8",8333,"1.1.1.1"},
        {"8.8.8.8",8333,"9.9.9.9"},{"::ffff:8.8.8.8",8333,"1.1.1.1"},
        {"2001:4860:4860::8888",8333,"2606:4700:4700::1111"},
        {"2001:470:abcd::1",8333,"2001:470:abcd::2"},
        {"2001:470:1bcd::1",18333,"1.1.1.1"},
        {"2002:0808:0808::1",8333,"1.1.1.1"},
        {"64:ff9b::808:808",8333,"1.1.1.1"},
        {"2001:0:4136:e378:8000:63bf:3fff:fdd2",8333,"1.1.1.1"},
        {"8.8.8.8",8333,"internal:seed.bitcoin.sipa.be"},
        {"127.0.0.1",18444,"127.0.0.2"},{"10.0.0.1",8333,"192.168.0.1"},
    };
    std::cout<<"key_label\tsecret_raw_hex\taddress\tport\tsource\taddress_group_hex\tsource_group_hex\tendpoint_key_hex\tnew_bucket\tnew_position\ttried_bucket\ttried_position\tnew_hash1\tnew_hash2\ttried_hash1\ttried_hash2\tnew_pos0\ttried_pos0\tnew_pos1\ttried_pos1\tnew_pos17\ttried_pos17\tnew_pos63\ttried_pos63\n";
    for(const auto& [label,key]:keys) for(const auto& row:rows) {
        const auto address=IP(row.address),source=IP(row.source);
        AddrInfo info{CAddress{CService{address,row.port},NODE_NONE},source};
        const auto ag=groups.GetGroup(address),sg=groups.GetGroup(source),ek=info.GetKey();
        const auto nh1=(HashWriter{}<<key<<ag<<sg).GetCheapHash();
        const auto nh2=(HashWriter{}<<key<<sg<<(nh1%uint32_t{64})).GetCheapHash();
        const auto th1=(HashWriter{}<<key<<ek).GetCheapHash();
        const auto th2=(HashWriter{}<<key<<ag<<(th1%uint32_t{8})).GetCheapHash();
        const int nb=info.GetNewBucket(key,source,groups),tb=info.GetTriedBucket(key,groups);
        std::cout<<label<<'\t'<<Hex(std::span{key.begin(),key.size()})<<'\t'<<row.address<<'\t'<<row.port<<'\t'<<row.source<<'\t'<<Hex(ag)<<'\t'<<Hex(sg)<<'\t'<<Hex(ek)<<'\t'<<nb<<'\t'<<info.GetBucketPosition(key,true,nb)<<'\t'<<tb<<'\t'<<info.GetBucketPosition(key,false,tb)<<'\t'<<nh1<<'\t'<<nh2<<'\t'<<th1<<'\t'<<th2;
        for(int bucket:{0,1,17,63})std::cout<<'\t'<<info.GetBucketPosition(key,true,bucket)<<'\t'<<info.GetBucketPosition(key,false,bucket);
        std::cout<<'\n';
    }
}
