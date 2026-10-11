// Matrix inputs come from the independent source audit; outputs only from linked Core methods.
#include <addrman.h>
#include <addrman_impl.h>
#include <bit>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
struct Row {const char* kind;const char* name;int64_t now,seen,last_try,last_success;int attempts;};
int main(){
 const std::vector<Row> rows{
  {"health","baseline",1700000000,1700000000,1699999399,0,0},
  {"health","future600",1700000000,1700000600,1699999399,0,0},
  {"health","future601",1700000000,1700000601,1699999399,0,0},
  {"health","age30d",1700000000,1697408000,1699999399,0,0},
  {"health","age30dplus1",1700000000,1697407999,1699999399,0,0},
  {"health","never_success2",1700000000,1700000000,1699999399,0,2},
  {"health","never_success3",1700000000,1700000000,1699999399,0,3},
  {"health","recent60protectsall",1700000000,1700000601,1699999940,0,255},
  {"health","recent61doesnotprotect",1700000000,1700000601,1699999939,0,255},
  {"health","futuretryprotects",1700000000,1697407999,1700010000,0,255},
  {"health","success7d10",1700000000,1700000000,1699999399,1699395200,10},
  {"health","success7dplus1_9",1700000000,1700000000,1699999399,1699395199,9},
  {"health","success7dplus1_10",1700000000,1700000000,1699999399,1699395199,10},
  {"health","recent_success_stale_seen",1700000000,1697407999,1699999399,1699999939,0},
  {"health","future_success_no_age_failure",1700000000,1700000000,1699999399,1700010000,10},
  {"weight","weight-0",1700000000,1700000000,1699999941,0,0},
  {"weight","weight-1",1700000000,1700000000,1699999941,0,1},
  {"weight","weight-2",1700000000,1700000000,1699999941,0,2},
  {"weight","weight-3",1700000000,1700000000,1699999941,0,3},
  {"weight","weight-4",1700000000,1700000000,1699999941,0,7},
  {"weight","weight-5",1700000000,1700000000,1699999941,0,8},
  {"weight","weight-6",1700000000,1700000000,1699999941,0,9},
  {"weight","weight-7",1700000000,1700000000,1699999941,0,255},
  {"weight","weight-8",1700000000,1700000000,1699999940,0,0},
  {"weight","weight-9",1700000000,1700000000,1699999940,0,1},
  {"weight","weight-10",1700000000,1700000000,1699999940,0,2},
  {"weight","weight-11",1700000000,1700000000,1699999940,0,3},
  {"weight","weight-12",1700000000,1700000000,1699999940,0,7},
  {"weight","weight-13",1700000000,1700000000,1699999940,0,8},
  {"weight","weight-14",1700000000,1700000000,1699999940,0,9},
  {"weight","weight-15",1700000000,1700000000,1699999940,0,255},
  {"weight","weight-16",1700000000,1700000000,1699999939,0,0},
  {"weight","weight-17",1700000000,1700000000,1699999939,0,1},
  {"weight","weight-18",1700000000,1700000000,1699999939,0,2},
  {"weight","weight-19",1700000000,1700000000,1699999939,0,3},
  {"weight","weight-20",1700000000,1700000000,1699999939,0,7},
  {"weight","weight-21",1700000000,1700000000,1699999939,0,8},
  {"weight","weight-22",1700000000,1700000000,1699999939,0,9},
  {"weight","weight-23",1700000000,1700000000,1699999939,0,255},
  {"weight","weight-24",1700000000,1700000000,1699999401,0,0},
  {"weight","weight-25",1700000000,1700000000,1699999401,0,1},
  {"weight","weight-26",1700000000,1700000000,1699999401,0,2},
  {"weight","weight-27",1700000000,1700000000,1699999401,0,3},
  {"weight","weight-28",1700000000,1700000000,1699999401,0,7},
  {"weight","weight-29",1700000000,1700000000,1699999401,0,8},
  {"weight","weight-30",1700000000,1700000000,1699999401,0,9},
  {"weight","weight-31",1700000000,1700000000,1699999401,0,255},
  {"weight","weight-32",1700000000,1700000000,1699999400,0,0},
  {"weight","weight-33",1700000000,1700000000,1699999400,0,1},
  {"weight","weight-34",1700000000,1700000000,1699999400,0,2},
  {"weight","weight-35",1700000000,1700000000,1699999400,0,3},
  {"weight","weight-36",1700000000,1700000000,1699999400,0,7},
  {"weight","weight-37",1700000000,1700000000,1699999400,0,8},
  {"weight","weight-38",1700000000,1700000000,1699999400,0,9},
  {"weight","weight-39",1700000000,1700000000,1699999400,0,255},
  {"weight","weight-40",1700000000,1700000000,1699999399,0,0},
  {"weight","weight-41",1700000000,1700000000,1699999399,0,1},
  {"weight","weight-42",1700000000,1700000000,1699999399,0,2},
  {"weight","weight-43",1700000000,1700000000,1699999399,0,3},
  {"weight","weight-44",1700000000,1700000000,1699999399,0,7},
  {"weight","weight-45",1700000000,1700000000,1699999399,0,8},
  {"weight","weight-46",1700000000,1700000000,1699999399,0,9},
  {"weight","weight-47",1700000000,1700000000,1699999399,0,255},
  {"weight","weight-48",1700000000,1700000000,1700010000,0,0},
  {"weight","weight-49",1700000000,1700000000,1700010000,0,1},
  {"weight","weight-50",1700000000,1700000000,1700010000,0,2},
  {"weight","weight-51",1700000000,1700000000,1700010000,0,3},
  {"weight","weight-52",1700000000,1700000000,1700010000,0,7},
  {"weight","weight-53",1700000000,1700000000,1700010000,0,8},
  {"weight","weight-54",1700000000,1700000000,1700010000,0,9},
  {"weight","weight-55",1700000000,1700000000,1700010000,0,255},
 };
 std::cout<<std::setprecision(std::numeric_limits<double>::max_digits10);
 for(const auto& row:rows){
  AddrInfo info;
  info.nTime=NodeSeconds{std::chrono::seconds{row.seen}};
  info.m_last_try=NodeSeconds{std::chrono::seconds{row.last_try}};
  info.m_last_success=NodeSeconds{std::chrono::seconds{row.last_success}};
  info.nAttempts=row.attempts;
  const NodeSeconds now{std::chrono::seconds{row.now}};
  const double chance=info.GetChance(now);
  std::cout<<"{\"kind\":\""<<row.kind<<"\",\"name\":\""<<row.name<<"\",\"now\":"<<row.now<<",\"seen\":"<<row.seen<<",\"last_try\":"<<row.last_try<<",\"last_success\":"<<row.last_success<<",\"attempts\":"<<row.attempts<<",\"terrible\":"<<(info.IsTerrible(now)?"true":"false")<<",\"chance\":"<<chance<<",\"chance_bits_hex\":\""<<std::hex<<std::bit_cast<uint64_t>(chance)<<std::dec<<"\"}\n";
 }
}
