#include "TimeLog.h"
using namespace std;
using namespace std::chrono;

void TimeLog::markTime(string mark) {
  pair<string, time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>>> p;
  p.first = mark;
  p.second = high_resolution_clock::now();
  marks.push_back(p);
}

void TimeLog::endMark(string mark) {
  endMarks[mark] = high_resolution_clock::now();
  endMarksKeys.push_back(mark);
}

int TimeLog::timeDiff(time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>> start,
                      time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>> stop) {
  return duration_cast<microseconds>(stop-start).count();
}

string TimeLog::getTimes() {
  string output = "";
  for(auto p : marks) {
    string mark = p.first;

    bool found = false;
    for(string s : endMarksKeys) {
      if(s.compare(mark) == 0) {
        found = true;
        break;
      }
    }
    if(!found) throw runtime_error("No key for :"+mark);

    output += mark + ": " + to_string(timeDiff(p.second, endMarks[mark])) + "ms\n";
  }
  return output;
}

TimeLog::TimeLog() {}
TimeLog::~TimeLog() {}
