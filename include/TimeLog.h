#ifndef TIMELOG_H
#define TIMELOG_H
#include "algorithm"
#include "chrono"
#include "fstream"
#include "iostream"
#include "map"
#include "cmath"
#include "string"
#include "vector"
using namespace std;
using namespace std::chrono;

class TimeLog {
  public:

    /*
      Mark time
    */
    void markTime(string mark);

    /*
      End mark
    */
    void endMark(string mark);

    /*
      Time difference in micro seconds
    */
    static int timeDiff(time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>> start,
                        time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>> stop);

    string getTimes();

    TimeLog();
    virtual ~TimeLog();

  protected:

  private:
    vector<string> endMarksKeys;
    map<string, time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>>> endMarks;
    vector<pair<string, time_point<chrono::_V2::system_clock, duration<long int, ratio<1, 1000000000>>>>> marks;
};

#endif // TIMELOG_H
