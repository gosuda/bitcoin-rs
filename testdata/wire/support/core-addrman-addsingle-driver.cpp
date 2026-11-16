// Calls the real AddSingle through Core's existing test friend boundary.
#include <addrman.h>
#include <addrman_impl.h>
#include <netgroup.h>
#include <hash.h>
#include <random.h>
#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <set>
using namespace std::chrono_literals;
CNetAddr IP(const std::string& text) {in_addr addr{}; if(inet_pton(AF_INET,text.c_str(),&addr)!=1) std::abort();return CNetAddr(addr);}
CService Service(const std::string& ip) {return CService{IP(ip),8333};}
class AddrManDeterministic {
    const NetGroupManager& groups;
    AddrManImpl book;
public:
    AddrManDeterministic(const NetGroupManager& g):groups{g},book{g,true,0} {book.nKey=(HashWriter{}<<int32_t{1}).GetHash();}
    int refs(const std::string& ip) {LOCK(book.cs);auto p=book.Find(Service(ip));return p?p->nRefCount:0;}
    int64_t seen(const std::string& ip) {LOCK(book.cs);auto p=book.Find(Service(ip));return p?TicksSinceEpoch<std::chrono::seconds>(p->nTime):-1;}
    bool has(const std::string& ip) {LOCK(book.cs);return book.Find(Service(ip))!=nullptr;}
    size_t size() {LOCK(book.cs);return book.mapInfo.size();}
    void health(const std::string& ip,int attempts,int64_t last_try,int64_t success=0) {LOCK(book.cs);auto p=book.Find(Service(ip));assert(p);p->nAttempts=attempts;p->m_last_try=NodeSeconds{std::chrono::seconds{last_try}};p->m_last_success=NodeSeconds{std::chrono::seconds{success}};}
    bool add(const std::string& ip,const std::string& source,int64_t seen,bool pass=true,int64_t penalty=0) {
        LOCK(book.cs);
        auto p=book.Find(Service(ip));
        const int refs=p?p->nRefCount:0;
        const int factor=1<<refs;
        // Choose a real Core PRNG seed that deterministically admits/refuses
        // the stochastic branch, without changing AddSingle or its RNG.
        for(uint64_t i=0;i<100000;++i) {
            uint256 seed;WriteLE64(seed.begin(),i);FastRandomContext trial{seed};
            const bool hit=trial.randrange(factor)==0;
            if(hit==pass || refs==0){book.insecure_rand.Reseed(seed);break;}
            if(i==99999)std::abort();
        }
        const CAddress addr{Service(ip),NODE_NETWORK,NodeSeconds{std::chrono::seconds{seen}}};
        return book.AddSingle(addr,IP(source),std::chrono::seconds{penalty});
    }
    void good(const std::string& ip,int64_t time=1700000000) {LOCK(book.cs);assert(book.Good_(Service(ip),false,NodeSeconds{std::chrono::seconds{time}}));}
    void attempt(const std::string& ip,bool count,int64_t time) {LOCK(book.cs);book.Attempt_(Service(ip),count,NodeSeconds{std::chrono::seconds{time}});}
    void stats(const std::string& label,const std::string& ip) {LOCK(book.cs);auto p=book.Find(Service(ip));assert(p);std::cout<<"{\"case\":\""<<label<<"\",\"attempts\":"<<p->nAttempts<<",\"seen\":"<<TicksSinceEpoch<std::chrono::seconds>(p->nTime)<<",\"last_try\":"<<TicksSinceEpoch<std::chrono::seconds>(p->m_last_try)<<",\"last_success\":"<<TicksSinceEpoch<std::chrono::seconds>(p->m_last_success)<<",\"tried\":"<<(p->fInTried?"true":"false")<<"}\n";}
    std::pair<int,int> slot(const std::string& ip,const std::string& src) {
        AddrInfo info{CAddress{Service(ip),NODE_NONE},IP(src)};
        const int b=info.GetNewBucket(book.nKey,IP(src),groups);
        return {b,info.GetBucketPosition(book.nKey,true,b)};
    }
};
void row(const std::string& label,bool accepted,AddrManDeterministic& book,const std::string& addr,const std::string& other="") {
    std::cout<<"{\"case\":\""<<label<<"\",\"accepted\":"<<(accepted?"true":"false")<<",\"records\":"<<book.size()<<",\"refs\":"<<book.refs(addr)<<",\"seen\":"<<book.seen(addr);
    if(!other.empty())std::cout<<",\"other_present\":"<<(book.has(other)?"true":"false")<<",\"other_refs\":"<<book.refs(other);
    std::cout<<"}\n";
}
int main() {
    SetMockTime(1700000000s);
    const auto groups=NetGroupManager::NoAsmap();
    const std::string target="8.8.8.8",source="1.1.1.1";
    AddrManDeterministic search{groups};
    std::vector<std::string> sources{source};std::set<int> buckets{search.slot(target,source).first};
    for(int i=2;sources.size()<10;++i){const std::string s="1."+std::to_string(i)+".1.1";if(buckets.insert(search.slot(target,s).first).second)sources.push_back(s);}
    std::string collider;
    for(int i=1;i<256;++i){const std::string a="8.8.9."+std::to_string(i);if(search.slot(a,source)==search.slot(target,source)){collider=a;break;}}
    assert(!collider.empty());
    std::cout<<"{\"independent_sources\":[";
    for(size_t i=0;i<sources.size();++i){if(i)std::cout<<',';std::cout<<'"'<<sources[i]<<'"';}std::cout<<"]}\n";
    std::cout<<"{\"fixture_target\":\""<<target<<"\",\"source\":\""<<source<<"\",\"collider\":\""<<collider<<"\",\"new_bucket\":"<<search.slot(target,source).first<<",\"new_position\":"<<search.slot(target,source).second<<"}\n";
    {
        AddrManDeterministic b{groups};row("first",b.add(target,source,1699999000),b,target);
        row("same-source-repeat",b.add(target,source,1699999001),b,target);
        row("other-source-rng-refused",b.add(target,sources[1],1699999001,false),b,target);
        for(int i=1;i<10;++i)row("source-"+std::to_string(i+1),b.add(target,sources[i],1699999001),b,target);
    }
    {
        AddrManDeterministic b{groups};b.add(target,source,1699999000);
        row("healthy-single-reference-collision",b.add(collider,source,1699999000),b,target,collider);
        b.add(target,sources[1],1699999001);
        row("fresh-replaces-redundant-reference",b.add(collider,source,1699999000),b,target,collider);
    }
    {
        AddrManDeterministic b{groups};b.add(target,source,1699999000);b.health(target,3,1699999800);
        row("failed-gossip-replaced",b.add(collider,source,1699999000),b,target,collider);
    }
    {
        AddrManDeterministic b{groups};b.add(target,source,1699999000);b.health(target,3,1699999940);
        row("recent-attempt-exact60-protected",b.add(collider,source,1699999000),b,target,collider);
    }
    {
        AddrManDeterministic b{groups};b.add(target,source,1699990000);
        row("time-update-zero-penalty-precedes-reference",b.add(target,sources[1],1699999000),b,target);
        row("time-penalty-still-new-info",b.add(target,sources[1],1700000000,true,7200),b,target);
    }
    {
        AddrManDeterministic b{groups};b.add(target,source,1699999000);b.good(target);
        row("tried-rejects-new-reference",b.add(target,sources[1],1699999001),b,target);
    }
    {
        AddrManDeterministic b{groups};const std::string other="9.9.9.9";
        b.add(target,source,1699999000);b.add(other,"2.2.2.2",1699999000);
        b.attempt(target,true,1700000000);b.stats("first-attempt-counted",target);
        b.attempt(target,true,1700000001);b.stats("repeat-same-good-epoch-not-counted",target);
        b.good(other,1700000010);
        b.attempt(target,false,1700000011);b.stats("noncounted-attempt-updates-only-try",target);
        b.attempt(target,true,1700000012);b.stats("attempt-after-other-good-counted",target);
        b.good(target,1700000020);b.stats("good-retains-seen-resets-attempts",target);
    }

}
