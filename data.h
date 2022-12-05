#include <set>
#include <vector>
#include <string>
using namespace std;
extern bool memflag, thflag, slow_get, slow_post, slow_read;
extern set<string> slow_get_ip;
extern set<string> slow_post_ip;
extern set<string> slow_read_ip;

void slowloris();
void slow_POST();
void slow_Read();
void thread_check();
void ram_check();
