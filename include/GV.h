#ifndef GV_H
#define GV_H
#include <string>
using namespace std;

/*
  Global Variables

  This class contains static constant variables
  such that they are easy to obtain from other
  classes
*/
class GV {
  public:
    static const int n1 = 3;
    static const int n2 = 3;
    inline static const string filename = "simple.txt";

    //network
    static const int PORT = 1212;
    inline static const string SERVER = "localhost";
    inline static const string ADDRESS = SERVER + ":" + to_string(PORT);

  protected:

  private:
};

#endif // GV_H
