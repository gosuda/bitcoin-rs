// Bounded operational oracle over unmodified pinned Core AddrManImpl.
#include <addrman.h>
#include <addrman_impl.h>
#include <netgroup.h>
#include <hash.h>
#include <random.h>
#include <arpa/inet.h>
#include <iostream>
#include <set>
using namespace std::chrono_literals;
constexpr int64_t NOW=1700000000;
CNetAddr IP(const std::string& text) {in_addr addr{};assert(inet_pton(AF_INET,text.c_str(),&addr)==1);return CNetAddr(addr);}
CService Endpoint(uint16_t port) {return CService{IP("8.8.8.8"),port};}
class AddrManDeterministic {
    const NetGroupManager& groups;
    AddrManImpl book;
public:
    AddrManDeterministic(const NetGroupManager& g):groups{g},book{g,true,0} {book.nKey=(HashWriter{}<<int32_t{1}).GetHash();}
    std::pair<int,int> tried(const CService& addr) const {
        AddrInfo info{CAddress{addr,NODE_NONE},IP("1.1.1.1")};
        const int bucket=info.GetTriedBucket(book.nKey,groups);
        return {bucket,info.GetBucketPosition(book.nKey,false,bucket)};
    }
    bool add(const CService& addr,const std::string& source,int64_t seen=NOW-100000) {
        LOCK(book.cs);
        auto p=book.Find(addr);const int count=p?p->nRefCount:0;
        for(uint64_t i=0;i<100000;++i){uint256 seed;WriteLE64(seed.begin(),i);FastRandomContext rng{seed};if(rng.randrange(1<<count)==0){book.insecure_rand.Reseed(seed);break;}if(i==99999)std::abort();}
        return book.AddSingle(CAddress{addr,NODE_NETWORK,NodeSeconds{std::chrono::seconds{seen}}},IP(source),0s);
    }
    bool good(const CService& addr,bool test,int64_t time){LOCK(book.cs);return book.Good_(addr,test,NodeSeconds{std::chrono::seconds{time}});}
    void attempt(const CService& addr,int64_t time,bool count=false){LOCK(book.cs);book.Attempt_(addr,count,NodeSeconds{std::chrono::seconds{time}});}
    void resolve(){book.ResolveCollisions();}
    void state(const std::string& label,const CService& old,const CService& candidate,const CService* victim=nullptr,const char* extra_label="victim"){
        LOCK(book.cs);assert(book.CheckAddrman()==0);
        std::cout<<"{\"case\":\""<<label<<"\",\"queue\":"<<book.m_tried_collisions.size()<<",\"last_good\":"<<TicksSinceEpoch<std::chrono::seconds>(book.m_last_good)<<",\"records\":"<<book.mapInfo.size()<<",\"new_count\":"<<book.nNew<<",\"tried_count\":"<<book.nTried;
        describe("incumbent",old);describe("challenger",candidate);if(victim)describe(extra_label,*victim);
        std::cout<<"}\n";
    }
    void describe(const char* label,const CService& addr){
        nid_type id;const auto p=book.Find(addr,&id);
        std::cout<<",\""<<label<<"\":{\"endpoint\":\""<<addr.ToStringAddrPort()<<"\",\"present\":"<<(p?"true":"false");
        if(p){size_t refs=0;std::vector<std::pair<int,int>> slots;for(int b=0;b<ADDRMAN_NEW_BUCKET_COUNT;++b)for(int pos=0;pos<ADDRMAN_BUCKET_SIZE;++pos)if(book.vvNew[b][pos]==id){++refs;slots.emplace_back(b,pos);}
            std::cout<<",\"tried\":"<<(p->fInTried?"true":"false")<<",\"refs\":"<<p->nRefCount<<",\"random_position\":"<<p->nRandomPos<<",\"table_refs\":"<<refs<<",\"seen\":"<<TicksSinceEpoch<std::chrono::seconds>(p->nTime)<<",\"last_success\":"<<TicksSinceEpoch<std::chrono::seconds>(p->m_last_success)<<",\"last_try\":"<<TicksSinceEpoch<std::chrono::seconds>(p->m_last_try)<<",\"attempts\":"<<p->nAttempts<<",\"primary_source\":\""<<p->source.ToStringAddr()<<'"';
            std::cout<<",\"new_slots\":[";for(size_t n=0;n<slots.size();++n){if(n)std::cout<<',';std::cout<<'['<<slots[n].first<<','<<slots[n].second<<']';}std::cout<<']';}
        std::cout<<'}';
    }
    void queue_for_test(const CService& addr){LOCK(book.cs);nid_type id;assert(book.Find(addr,&id));book.m_tried_collisions.insert(id);}
    void drop_new_for_test(const CService& addr){LOCK(book.cs);nid_type id;const auto p=book.Find(addr,&id);assert(p&&!p->fInTried);std::vector<std::pair<int,int>> slots;for(int b=0;b<ADDRMAN_NEW_BUCKET_COUNT;++b)for(int pos=0;pos<ADDRMAN_BUCKET_SIZE;++pos)if(book.vvNew[b][pos]==id)slots.emplace_back(b,pos);for(auto [b,pos]:slots)book.ClearNew(b,pos);}
    void histogram(const CService& first,const CService& second){int a=0,b=0;for(int n=0;n<1024;++n){const auto [addr,last_try]=book.SelectTriedCollision();if(addr==first){++a;assert(last_try==NodeSeconds{std::chrono::seconds{NOW-20000}});}else{assert(addr==second);++b;assert(last_try==NodeSeconds{std::chrono::seconds{NOW-1234}});}}std::cout<<"{\"case\":\"two-collision-selection\",\"draws\":1024,\"first_count\":"<<a<<",\"second_count\":"<<b<<",\"first\":\""<<first.ToStringAddrPort()<<"\",\"second\":\""<<second.ToStringAddrPort()<<"\"}\n";}
    void creation_order(const CService& first,const CService& second){LOCK(book.cs);nid_type first_id,second_id;assert(book.Find(first,&first_id));assert(book.Find(second,&second_id));assert(first_id<second_id);std::cout<<"{\"case\":\"creation-order-fixture\",\"created_first\":\""<<first.ToStringAddrPort()<<"\",\"first_creation_id\":"<<first_id<<",\"created_second\":\""<<second.ToStringAddrPort()<<"\",\"second_creation_id\":"<<second_id<<",\"good_call_order\":[\""<<second.ToStringAddrPort()<<"\",\""<<first.ToStringAddrPort()<<"\"],\"core_collision_iteration\":[";bool comma=false;for(auto id:book.m_tried_collisions){if(comma)std::cout<<',';comma=true;std::cout<<'"'<<book.mapInfo.at(id).ToStringAddrPort()<<'"';}std::cout<<"]}\n";}
    void connected_good(const CService& addr){assert(!book.Good(addr,NodeSeconds{std::chrono::seconds{NOW}}));}
    void select_new(const std::string& label,const CService& expected){const auto [addr,last_try]=book.Select(true,{});assert(addr==expected);std::cout<<"{\"case\":\""<<label<<"\",\"selected\":\""<<addr.ToStringAddrPort()<<"\",\"last_try\":"<<TicksSinceEpoch<std::chrono::seconds>(last_try)<<"}\n";}
    void select(const std::string& label){const auto [addr,last_try]=book.SelectTriedCollision();std::cout<<"{\"case\":\""<<label<<"\",\"selected\":\""<<addr.ToStringAddrPort()<<"\",\"last_try\":"<<TicksSinceEpoch<std::chrono::seconds>(last_try)<<"}\n";}
};
int main(){
    SetMockTime(std::chrono::seconds{NOW});const auto groups=NetGroupManager::NoAsmap();
    AddrManDeterministic search{groups};const auto old=Endpoint(8333);
    std::vector<CService> colliders;
    for(unsigned port=1;port<=65535 && colliders.size()<12;++port){if(port==8333)continue;auto addr=Endpoint(port);if(search.tried(addr)==search.tried(old))colliders.push_back(addr);}
    assert(colliders.size()==12);const auto challenger=colliders[0];
    std::cout<<"{\"fixture\":\"hash-int32-1\",\"now\":"<<NOW<<",\"tried_bucket\":"<<search.tried(old).first<<",\"tried_position\":"<<search.tried(old).second<<",\"incumbent\":\""<<old.ToStringAddrPort()<<"\",\"colliders\":[";
    for(size_t i=0;i<colliders.size();++i){if(i)std::cout<<',';std::cout<<'"'<<colliders[i].ToStringAddrPort()<<'"';}std::cout<<"]}\n";
    struct Timing {const char* name;int64_t success_age,try_age,challenger_age;};
    for(const auto& t:std::vector<Timing>{
        {"success14399-protects",14399,61,2401},
        {"success14400-attempt61-replaces",14400,61,30},
        {"success14401-attempt61-replaces",14401,61,30},
        {"attempt59-waits",20000,59,2401},
        {"attempt60-waits",20000,60,2401},
        {"attempt61-replaces",20000,61,30},
        {"attempt14399-replaces",20000,14399,30},
        {"attempt14400-window2399-waits",20000,14400,2399},
        {"attempt14400-window2400-waits",20000,14400,2400},
        {"attempt14400-window2401-replaces",20000,14400,2401},
        {"attempt14401-window2401-replaces",20000,14401,2401},
        {"future-incumbent-success-protects",-1,-1,2401},
        {"future-incumbent-attempt-waits",20000,-1,2401},
        {"future-challenger-success-waits",20000,20000,-1},
    }){
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-t.success_age));b.attempt(old,NOW-t.try_age);
        assert(b.add(challenger,"2.2.2.2"));assert(!b.good(challenger,true,NOW-t.challenger_age));b.attempt(challenger,NOW-5,true);
        std::cout<<"{\"timing\":\""<<t.name<<"\",\"success_age\":"<<t.success_age<<",\"try_age\":"<<t.try_age<<",\"challenger_age\":"<<t.challenger_age<<"}\n";
        b.state(std::string{t.name}+"-before",old,challenger);b.select(std::string{t.name}+"-select");b.resolve();b.state(std::string{t.name}+"-after",old,challenger);
    }
    {
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));
        assert(b.add(challenger,"2.2.2.2"));assert(!b.good(challenger,true,NOW-2401));
        assert(!b.good(challenger,true,NOW-1));b.resolve();b.state("repeat-good-refreshes-window",old,challenger);
    }
    {
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-1));
        assert(b.add(challenger,"2.2.2.2"));b.attempt(challenger,NOW-5,true);assert(b.good(challenger,false,NOW));
        b.state("good-false-explicit-bypass",old,challenger);
    }
    for(bool extra_victim_ref:{false,true}){
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));
        const CService victim{IP("8.8.9.89"),8333};assert(b.add(victim,"1.1.1.1"));
        if(extra_victim_ref)assert(b.add(victim,"3.3.3.3",NOW-99999));
        assert(b.add(challenger,"2.2.2.2"));
        for(unsigned source=4;source<11;++source)assert(b.add(challenger,"1."+std::to_string(source)+".1.1",NOW-99999));
        assert(!b.good(challenger,true,NOW-30));b.attempt(challenger,NOW-5,true);b.attempt(old,NOW-61);
        const std::string label=extra_victim_ref?"demotion-preserves-victim-other-ref":"demotion-deletes-victim-last-ref";
        b.state(label+"-before",old,challenger,&victim);b.resolve();b.state(label+"-after",old,challenger,&victim);
    }
    {
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));
        for(size_t i=0;i<11;++i){assert(b.add(colliders[i],"1."+std::to_string(i+2)+".1.1"));assert(!b.good(colliders[i],true,NOW-30));b.state("queue-add-"+std::to_string(i+1),old,colliders[i]);}
        b.select("queue10-select-incumbent");assert(!b.good(colliders[0],true,NOW));b.state("queue10-repeat-duplicate",old,colliders[0]);
    }
    {
        // Defensive queue state with a vacant target slot; only queue setup is synthetic.
        AddrManDeterministic b{groups};assert(b.add(challenger,"2.2.2.2"));b.attempt(challenger,NOW-5,true);b.queue_for_test(challenger);
        b.state("vacant-slot-before",old,challenger);b.resolve();b.state("vacant-slot-after",old,challenger);
    }
    for(bool through_select:{false,true}){
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));assert(b.add(challenger,"2.2.2.2"));assert(!b.good(challenger,true,NOW-30));b.drop_new_for_test(challenger);
        const std::string name=through_select?"missing-challenger-select":"missing-challenger-resolve";b.state(name+"-before",old,challenger);
        if(through_select)b.select(name+"-result");else b.resolve();b.state(name+"-after",old,challenger);
    }
    {
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));assert(b.add(challenger,"2.2.2.2"));assert(!b.good(challenger,true,NOW-30));assert(b.good(challenger,false,NOW-1));b.state("already-promoted-before",old,challenger);b.resolve();b.state("already-promoted-after",old,challenger);
    }
    {
        CService old2=Endpoint(8334),new2;
        assert(search.tried(old2)!=search.tried(old));
        for(unsigned port=1;port<=65535;++port){const auto candidate=Endpoint(port);if(candidate!=old2 && search.tried(candidate)==search.tried(old2)){new2=candidate;break;}}
        assert(new2.GetPort()!=0);AddrManDeterministic b{groups};
        assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));assert(b.add(old2,"4.4.4.4"));assert(b.good(old2,false,NOW-20000));b.attempt(old2,NOW-1234);
        assert(b.add(challenger,"2.2.2.2"));assert(!b.good(challenger,true,NOW-30));assert(b.add(new2,"3.3.3.3"));assert(!b.good(new2,true,NOW-30));b.histogram(old,old2);
    }

    {
        // Models net.cpp's external AlreadyConnectedToAddress=true branch.
        // It does not infer connection status from AddrMan or model native pending guards.
        AddrManDeterministic b{groups};assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));b.attempt(old,NOW-1234);assert(b.add(challenger,"2.2.2.2"));assert(!b.good(challenger,true,NOW-30));
        b.select("already-connected-collision-selection");b.connected_good(old);b.state("already-connected-after-good",old,challenger);b.select_new("already-connected-new-selection",challenger);b.resolve();b.state("already-connected-after-resolve",old,challenger);
    }

    {
        // Creation order, not successful-notification order, orders Core's ID set.
        AddrManDeterministic b{groups};const auto first=colliders[0],second=colliders[1];
        assert(b.add(old,"1.1.1.1"));assert(b.good(old,false,NOW-20000));b.attempt(old,NOW-61);
        assert(b.add(first,"2.2.2.2"));assert(b.add(second,"3.3.3.3"));
        assert(!b.good(second,true,NOW-30));assert(!b.good(first,true,NOW-30));
        b.attempt(first,NOW-5,true);b.attempt(second,NOW-5,true);
        b.creation_order(first,second);b.state("creation-order-before",old,first,&second,"second_challenger");
        b.resolve();b.state("creation-order-after",old,first,&second,"second_challenger");
    }

}
