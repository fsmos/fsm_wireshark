#include "config.h"
#include <epan/packet.h>

static int proto_fsm = -1;
static gint ett_fsm = -1;
static int hf_fsm_pkt_type = -1;
static int  hf_fsm_device_type;
static int hf_fsm_device_vid;
static int hf_fsm_device_podvid;
static int hf_fsm_device_kod;
static int hf_fsm_device_id;
static int hf_fsm_crc;
static int hf_fsm_cmd;
static int hf_fsm_cmd_count;
static int hf_fsm_len16;
static int hf_fsm_len8;
static int hf_fsm_alg;
static int hf_fsm_number;
static int hf_fsm_lennumber;
static int hf_fsm_email;
static int hf_fsm_lenemail;
static int hf_fsm_Data;
static int hf_fsm_login;
static int hf_fsm_lenlogin;
static int hf_fsm_sctype;
static int hf_fsm_ID_Signal;
static int hf_fsm_codec;


static const value_string fsm_packettypes[] = {
   {1,"Регистрация устройства"},
   {2,"Подтверждение регистрации"},
   {3,"Удаление устройства из списка"},
   {4,"Подтверждение удаления устройства из списка"},
   {5,"Пинг"},
   {6,"Отправка команды устройству"},
   {7,"Подтверждение приёма команды устройством"},
   {8,"Ответ на команду устройством"},
   {9,"Подтверждение приёма команды сервером"},
   {10,"Отправка команды серверу"},
   {11,"Отправка текстового сообщения"},
   {12,"Подтверждение приёма текстового сообщения"},
   {13,"Отправка зашифрованного текстового сообщения"},
   {14,"Подтверждение приёма зашифрованного текстового сообщения"},
   {15,"Передача аудио данных"},
   {16,"Передача видео данных"},
   {17,"Передача бинарных данных"},
   {18,"Подтверждение приёма бинарных данных"},
   {19,"Отправить СМС"},
   {20,"Подтверждение СМС"},
   {21,"Передача СМС устройству"},
   {22,"Подтверждение СМС устройством"},
   {23,"Отправить зашифрованного СМС" },
   {24,"Подтверждение зашифрованного СМС"},
   {25,"Отправить зашифрованного СМС устройству"},
   {26,"Подтверждение зашифрованного СМС  устройства"},
   {27,"Отправка email"},
   {28,"Подтверждение email"},
   {29,"Передача email устройству"},
   {30,"Подтверждение email устройством"},
   {31,"Отправить зашифрованного email"},
   {32,"Подтверждение зашифрованного email"},
   {33,"Отправить зашифрованного email устройству"},
   {34,"Подтверждение зашифрованного email   устройства"},
   {35,"Отправка сообщение в социальную сеть"},
   {36,"Подтверждение сообщения в социальную сеть"},
   {37,"Передача сообщения в социальную сеть устройству"},
   {38,"Подтверждение   сообщения в социальную сеть устройством"},
   {39,"Отправить зашифрованного сообщения в социальную сеть"},
   {40,"Подтверждение зашифрованного сообщения в социальную сеть"},
   {41,"Отправить зашифрованного сообщения в социальную сеть устройству"},
   {42,"Подтверждение зашифрованного сообщения в социальную сеть устройства"},
   {43,"Тревога"},
   {44,"Предупреждение"},
   {45,"Сбой"},
   {46,"Звуковой сигнал"},
   {0, NULL }
};
static const value_string fsm_devicetypes[] = {
   {1,"Автоматически Электрощиток"},
   {2,"Умная Теплица"},
   {3,"Смартфон"},
   {4,"Устройство аудио связи"},
   {5,"Сеть"},
   {6,"Модуль статистики и конфигурации"},
   {0, NULL }
};
enum FSM_CodeOperation
{
  RegDevice=1, ///< Регистрация устройства
  AnsRegDevice=2, ///< Подтверждение регистрации
  DelLisr=3, ///< Удаление устройства из списка
  AnsDelList=4,///< Подтверждение удаления устройства из списка
  AnsPing=5, ///< Пинг
  SendCmdToDevice=6,///< Отправка команды устройству
  AnsSendCmdToDevice=7, ///< Подтверждение приёма команды устройством
  RqToDevice=8, ///< Ответ на команду устройством
  AnsRqToDevice=9,///< Подтверждение приёма команды сервером
  SendCmdToServer=10,///< Отправка команды серверу
  SendTxtMassage=11,///< Отправка текстового сообщения
  AnsSendTxtMassage=12, ///< Подтверждение приёма текстового сообщения
  SendTxtEncMassage=13, ///< Отправка зашифрованного текстового сообщения
  AnsSendTxtEncMassage=14, ///< Подтверждение приёма зашифрованного текстового сообщения
  SendAudio=15,///< Передача аудио данных
  SendVideo=16,///< Передача видео данных
  SendBinData=17,///< Передача бинарных данных
  AnsSendBinData=18,///< Подтверждение приёма бинарных данных
  SendSMS=19,///< Отправить СМС
  SendAnsSMS=20,///< Подтверждение СМС
  SendSMStoDev=21,///< Передача СМС устройству
  SendAnsSMStoDev=22,///< Подтверждение СМС устройством
  SendEncSMS=23, ///< Отправить зашифрованного СМС
  SendAnsEncSMS=24, ///<Подтверждение зашифрованного СМС
  SendEncSMStoDev=25,///< Отправить зашифрованного СМС устройству
  SendAnsEncSMStoDev=26,///< Подтверждение зашифрованного СМС  устройства
  SendEmail=27,///< Отправка email
  AnsEmail=28,///<Подтверждение email
  SendEmailtoDevice=29,///<Передача email устройству
  AnsSendEmailtoDevice=30,///<Подтверждение email устройством
  SendEncEmail=31,///<Отправить зашифрованного email
  AnsEncEmail=32,///<Подтверждение зашифрованного email
  SendEncEmailtoDev=33,///< Отправить зашифрованного email устройству
  AnsEncEmailtoDev=34,///< Подтверждение зашифрованного email   устройства
  SocSend=35,///< Отправка сообщение в социальную сеть
  AnsSocSend=36,///< Подтверждение сообщения в социальную сеть
  SocSendtoDev=37,///< Передача сообщения в социальную сеть устройству
  AnsSocSendtoDev=38,///< Подтверждение   сообщения в социальную сеть устройством
  SocEncSend=39,///< Отправить зашифрованного сообщения в социальную сеть
  AnsSocEncSend=40,///< Подтверждение зашифрованного сообщения в социальную сеть
  SocEncSendtoDev=41,///<	Отправить зашифрованного сообщения в социальную сеть устройству
  AnsSocEncSendtoDev=42,///<	Подтверждение зашифрованного сообщения в социальную сеть   устройства
  Alern=43,///<Тревога
  Warning=44,///<Предупреждение
  Trouble=45,///<Сбой
  Beep=46 ///<Звуковой сигнал

};

static void dissect_fsm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 packet_version = tvb_get_guint8(tvb, 0);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FSM");
    col_clear(pinfo->cinfo, COL_INFO);
    if (tree) {
        proto_item *ti = NULL;
        proto_tree *fsm_tree = NULL;

        ti = proto_tree_add_item(tree, proto_fsm, tvb, 0, -1, FALSE);
        fsm_tree = proto_item_add_subtree(ti, ett_fsm);
        proto_tree_add_item(fsm_tree, hf_fsm_pkt_type, tvb, 0, 1, FALSE);
    switch(packet_version)
    {
          case RegDevice: ///< Регистрация устройства
          proto_tree_add_item(fsm_tree, hf_fsm_device_type,tvb, 1, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_vid,tvb, 2, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_podvid,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_kod,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 5, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 7, 1, FALSE);
          break;
          case AnsRegDevice: ///< Подтверждение регистрации
            proto_tree_add_item(fsm_tree, hf_fsm_device_type,tvb, 1, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_vid,tvb, 2, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_podvid,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_kod,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 5, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 7, 1, FALSE);
          break;
          case DelLisr: ///< Удаление устройства из списка
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 3, 1, FALSE);
          break;
          case AnsDelList: ///< Подтверждение удаления устройства из списка
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 3, 1, FALSE);
          break;
          case AnsPing:///< Пинг
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 3, 1, FALSE);
          break;
          case SendCmdToDevice:///< Отправка команды устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd_count,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 6, -1, FALSE);
          break;
          case AnsSendCmdToDevice: ///< Подтверждение приёма команды устройством
           proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 4, 1, FALSE);
          break;
          case RqToDevice:///< Ответ на команду устройством
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd_count,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 6, -1, FALSE);
          break;
          case AnsRqToDevice: ///< Подтверждение приёма команды сервером
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 4, 1, FALSE);
          break;
          case SendCmdToServer: ///< Отправка команды серверу
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_cmd_count,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 6, -1, FALSE);
           break;
          case SendTxtMassage: ///< Отправка текстового сообщения
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 6, -1, FALSE);
           break;
          case AnsSendTxtMassage: ///< Подтверждение приёма текстового сообщения
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);
           break;
          case SendTxtEncMassage: ///< Отправка зашифрованного текстового сообщения
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 6, -1, FALSE);
           break;
          case AnsSendTxtEncMassage: ///< Подтверждение приёма зашифрованного текстового сообщения
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 4, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE); 
          break;
          case SendAudio:///< Передача аудио данных
           proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_codec,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 4, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 6, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 7, -1, FALSE);
          break;
          case SendVideo:///< Передача видео данных
             proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_codec,tvb, 3, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 4, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 6, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 7, -1, FALSE);
           break;
          case SendBinData:///< Передача бинарных данных
             proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 6, -1, FALSE);
           break;
          case AnsSendBinData:///< Подтверждение приёма бинарных данных
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 5, 1, FALSE);       
           break;
          case SendSMS: ///< Отправить СМС
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 30, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 32, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 33, -1, FALSE);
           break;
          case SendAnsSMS: ///< Подтверждение СМС
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 30, 1, FALSE);       
          break;
          case SendSMStoDev: ///< Передача СМС устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 30, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 32, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 33, -1, FALSE);
          break;
          case SendAnsSMStoDev: ///< Подтверждение СМС устройством
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 30, 1, FALSE); 
          break;
          case SendEncSMS: ///< Отправить зашифрованного СМС
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 30, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 31, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 32, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 33, -1, FALSE);
          break;
          case SendAnsEncSMS: ///<Подтверждение зашифрованного СМС
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 30, 1, FALSE); 
          break;
          case SendEncSMStoDev:///< Отправить зашифрованного СМС устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 30, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 31, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 32, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 33, -1, FALSE);
          break;
          case SendAnsEncSMStoDev:///< Подтверждение зашифрованного СМС  устройства
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lennumber,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_number,tvb, 5, 15, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 30, 1, FALSE); 
          break;
          case SendEmail:  ///< Отправка email
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 40, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 42, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 43, -1, FALSE);
          break;
          case AnsEmail: ///<Подтверждение email
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);       
          break;
          case SendEmailtoDevice: ///<Передача email устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 40, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 42, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 43, -1, FALSE);
          break;
          case AnsSendEmailtoDevice: ///<Подтверждение email устройством
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case SendEncEmail: ///<Отправить зашифрованного email
           proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 40, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 41, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 42, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 43, -1, FALSE);
          break;
          case AnsEncEmail: ///<Подтверждение зашифрованного email
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case SendEncEmailtoDev: ///< Отправить зашифрованного email устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 40, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 41, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 42, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 43, -1, FALSE);
          break;
          case AnsEncEmailtoDev: ///< Подтверждение зашифрованного email   устройства
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenemail,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_email,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case SocSend: ///< Отправка сообщение в социальную сеть
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_sctype,tvb, 40, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 41, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 43, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 44, -1, FALSE);
          break;
          case AnsSocSend: ///< Подтверждение сообщения в социальную сеть
           proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case SocSendtoDev:///< Передача сообщения в социальную сеть устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_sctype,tvb, 40, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len16,tvb, 41, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 43, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 44, -1, FALSE);
          break;
          case AnsSocSendtoDev:///< Подтверждение   сообщения в социальную сеть устройством
                  proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case SocEncSend: ///< Отправить зашифрованного сообщения в социальную сеть
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_sctype,tvb, 40, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 41, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 42, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 43, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 44, -1, FALSE);
          break;
          case AnsSocEncSend: ///< Подтверждение зашифрованного сообщения в социальную сеть
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case SocEncSendtoDev: ///<	Отправить зашифрованного сообщения в социальную сеть устройству
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_sctype,tvb, 40, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_alg,tvb, 41, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_len8,tvb, 42, 1, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 43, 1, FALSE);       
          proto_tree_add_item(fsm_tree, hf_fsm_Data,tvb, 44, -1, FALSE);
          break;
          case AnsSocEncSendtoDev: ///<	Подтверждение зашифрованного сообщения в социальную сеть   устройства
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_lenlogin,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_login,tvb, 5, 25, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 40, 1, FALSE);  
          break;
          case Alern: ///<Тревога
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_ID_Signal,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 4, 1, FALSE); 
          break;
          case Warning: ///<Предупреждение
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_ID_Signal,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 4, 1, FALSE); 
          break;
          case Trouble: ///<Сбой
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_ID_Signal,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 4, 1, FALSE); 
          break;
          case Beep: ///<Звук
          proto_tree_add_item(fsm_tree, hf_fsm_device_id,tvb, 1, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_ID_Signal,tvb, 3, 2, FALSE);
          proto_tree_add_item(fsm_tree, hf_fsm_crc,tvb, 4, 1, FALSE); 
          break;
    }
}

}

void proto_register_fsm(void)
{
    static hf_register_info hf[] = {
        { &hf_fsm_pkt_type,
            { "Тип", "fsm.packet.type",
            FT_UINT8, BASE_DEC,
            VALS(fsm_packettypes), 0x0,
            NULL, HFILL }
        },
       { &hf_fsm_device_type,
            { "Тип Устройства", "fsm.device.type",
            FT_UINT8, BASE_DEC,
            VALS(fsm_devicetypes), 0x0,
            NULL, HFILL }
        },
         { &hf_fsm_device_vid,
            { "Вид Устройства", "fsm.device.vid",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_device_podvid,
            { "Подвид Устройства", "fsm.device.podvid",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_fsm_device_kod,
            { "Код Устройства", "fsm.device.kod",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_device_id,
            { "ID Устройства", "fsm.device.id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
         { &hf_fsm_crc,
            { "CRC", "fsm.crc",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_cmd,
            { "Команда", "fsm.cmd",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_cmd_count,
            { "Количество команд", "fsm.cmd_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
          { &hf_fsm_Data,
            { "Data", "fsm.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_len16,
            { "Размер пакета", "fsm.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_len8,
            { "Размер пакета", "fsm.len",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
          { &hf_fsm_alg,
            { "Алгоритм шифрования", "fsm.alg",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_codec,
            { "Кодек", "fsm.codec",
            FT_UINT8,BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_number,
            { "Номер", "fsm.number",
            FT_BYTES,BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_lennumber,
            { "Длина Номера", "fsm.number.len",
            FT_UINT8,BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_email,
            { "email", "fsm.email",
            FT_STRING,BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_lenemail,
            { "Длина email", "fsm.email.len",
            FT_UINT8,BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fsm_login,
            { "Login", "fsm.login",
            FT_STRING,BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { & hf_fsm_lenlogin,
            { "Длина Login", "fsm.login.len",
            FT_UINT8,BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { & hf_fsm_sctype,
            { "Тип Соцсети", "fsm.login.soctype",
            FT_UINT8,BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { & hf_fsm_ID_Signal,
            { "Тип Соцсети", "fsm.signal.id",
            FT_UINT8,BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = { &ett_fsm };

   
    proto_fsm = proto_register_protocol (
        "FSM Protocol", /* полное имя */
        "FSM",          /* короткое имя */
        "fsm"           /* аббревиатура */
        ); 

    proto_register_field_array(proto_fsm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_fsm(void)
{
    static dissector_handle_t fsm_handle;

    fsm_handle = create_dissector_handle(dissect_fsm, proto_fsm);
    dissector_add_uint("ethertype", 0x1996, fsm_handle);
}


