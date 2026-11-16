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
#include <util/asmap.h>
#include <fstream>
#include <filesystem>
#include <iterator>
int main(int argc,char** argv) {
    std::array<unsigned char,32> ramp{};
    for(unsigned i=0;i<ramp.size();++i)ramp[i]=i;
    const std::vector<std::pair<std::string,uint256>> keys{{"hash-int32-1",(HashWriter{}<<int32_t{1}).GetHash()},{"ramp-00-1f",uint256{ramp}}};
    struct Row {const char* address;uint16_t port;const char* source;};
    const std::vector<Row> rows{
        {"250.1.1.1",8333,"250.1.1.1"},{"250.1.2.1",8333,"250.1.2.1"},
        {"250.1.1.1",9999,"250.1.1.1"},{"101.1.1.1",8333,"101.2.1.1"},
        {"101.8.1.1",8333,"250.1.1.1"},
        {"8.8.8.8",8333,"1.1.1.1"},{"::ffff:8.8.8.8",8333,"1.1.1.1"},
        {"2002:0808:0808::1",8333,"1.1.1.1"},{"64:ff9b::808:808",8333,"1.1.1.1"},
        {"::ffff:0:808:808",8333,"1.1.1.1"},{"2001:0:0:0:0:0:f7f7:f7f7",8333,"1.1.1.1"},
        {"64:ff9b:1::808:808",8333,"1.1.1.1"},{"2001:4860:4860::8888",8333,"1.1.1.1"},
        {"8.8.1.1",8333,"9.9.9.9"},{"9.9.9.9",8333,"8.8.1.1"},
        {"2001:470:abcd::1",8333,"2001:470:abcd::2"},
        {"406c:820b:272a:c045:b74e:fc0a:9ef2:cecc",8333,"46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac"},
        {"46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac",8333,"406c:820b:272a:c045:b74e:fc0a:9ef2:cecc"},
        {"0:1559:183:3728:224c:65a5:62e6:e991",8333,"8.8.8.8"},
        {"a77:7cd4:4be5:a449:89f2:3212:78c6:ee38",8333,"1.1.1.1"},
        {"378e:7290:54e5:bd36:4760:971c:e9b9:570d",8333,"a77:7cd4:4be5:a449:89f2:3212:78c6:ee38"},
        {"4.4.4.4",8333,"8.8.0.1"},{"4.4.4.4",8333,"8.8.1.1"},{"4.4.4.4",8333,"9.9.0.1"},
        {"8.8.8.8",8333,"internal:seed.bitcoin.sipa.be"},
        {"127.0.0.1",18444,"127.0.0.2"},{"10.0.0.1",8333,"192.168.0.1"},
        {"192.0.2.1",8333,"2001:db8::1"},
    };
    std::cout<<"map\tkey_label\tsecret_raw_hex\taddress\tport\tsource\taddress_asn\tsource_asn\taddress_group_hex\tsource_group_hex\tendpoint_key_hex\tnew_bucket\tnew_position\ttried_bucket\ttried_position\n";
    for(int arg=1;arg<argc;++arg) {
        std::ifstream file{argv[arg],std::ios::binary};
        std::vector<unsigned char> raw{std::istreambuf_iterator<char>(file),{}};
        assert(file.is_open() && !file.bad());
        std::vector<std::byte> bytes;
        for(auto b:raw)bytes.push_back(std::byte{b});
        assert(SanityCheckAsmap(bytes,128));
        const auto groups=NetGroupManager::WithLoadedAsmap(std::move(bytes));
        const auto label=std::filesystem::path{argv[arg]}.filename().string();
        if(label=="asmap.raw") {
            AddrInfo a{CAddress{CService{IP("250.1.1.1"),8333},NODE_NONE},IP("250.1.1.1")};
            AddrInfo b{CAddress{CService{IP("250.1.2.1"),8333},NODE_NONE},IP("250.1.2.1")};
            assert(a.GetTriedBucket(keys[0].second,groups)==236);
            assert(b.GetNewBucket(keys[0].second,groups)==795);
        }
        for(const auto& [key_label,key]:keys)for(const auto& row:rows) {
            const auto address=IP(row.address),source=IP(row.source);
            AddrInfo info{CAddress{CService{address,row.port},NODE_NONE},source};
            const int nb=info.GetNewBucket(key,source,groups),tb=info.GetTriedBucket(key,groups);
            std::cout<<label<<'\t'<<key_label<<'\t'<<Hex(std::span{key.begin(),key.size()})<<'\t'<<row.address<<'\t'<<row.port<<'\t'<<row.source<<'\t'<<groups.GetMappedAS(address)<<'\t'<<groups.GetMappedAS(source)<<'\t'<<Hex(groups.GetGroup(address))<<'\t'<<Hex(groups.GetGroup(source))<<'\t'<<Hex(info.GetKey())<<'\t'<<nb<<'\t'<<info.GetBucketPosition(key,true,nb)<<'\t'<<tb<<'\t'<<info.GetBucketPosition(key,false,tb)<<'\n';
        }
    }
}
