#include <bits/stdc++.h>
using namespace std;

int main () {
    vector<string> offset = {"0x7b4654436f636970", "0x355f31346d316e34", "0x3478345f33317937", "0x65355f673431665f", "0x7d346263623736"};
    reverse(offset.begin(), offset.end());
    for (auto i: offset) cout << i << ",";
    cout << endl;
}
