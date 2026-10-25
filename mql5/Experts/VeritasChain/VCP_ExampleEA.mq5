//+------------------------------------------------------------------+
//| VCP_ExampleEA.mq5 - example only: records the order and deal     |
//| transactions of one magic number as unsigned VCP v1.2 events.    |
//| Sign and batch them outside the terminal with `vcp seal`. This   |
//| EA does not trade.                                               |
//|                                                                  |
//| Only transactions whose magic number equals InpMagic are         |
//| recorded, so other EAs' and manual activity is not attributed to |
//| InpActorID. Events: ORD when an order is placed, EXE for each    |
//| deal, CXL when an order is cancelled or expires, ERR_REJECT when |
//| it is rejected.                                                  |
//|                                                                  |
//| Files: MQL5/Files/vcp-<ChainID>-<YYYYMMDD>.jsonl, one per UTC    |
//| day. A new day's file continues SequenceNum and PrevHash from    |
//| the previous file, so each closed file can be sealed as one      |
//| batch (see mql5/README.md).                                      |
//+------------------------------------------------------------------+
#property description "Records one magic number's order and deal transactions as unsigned VCP v1.2 events (example; does not trade)."
#include <VeritasChain/VCP.mqh>

input string InpActorID  = "mt5-example-ea";
input string InpPolicyID = "org.example:silver-mt5";
input long   InpMagic    = 70010;
input bool   InpPrevHash = true;

CVcpWriter g_writer;
string     g_chain  = "";
string     g_prefix = "";
string     g_day    = "";

//--- letters, digits, '.', '_' and '-' are kept; anything else becomes '_'
string SafeName(const string s)
  {
   string out = s;
   for(int i = 0; i < StringLen(out); i++)
     {
      ushort c = StringGetCharacter(out, i);
      bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
      if(!keep)
         StringSetCharacter(out, i, '_');
     }
   return out;
  }

string DayOf(const datetime t)
  {
   MqlDateTime d;
   TimeToStruct(t, d);
   return StringFormat("%04d%02d%02d", d.year, d.mon, d.day);
  }

//--- size of a file in MQL5/Files, or -1 if it does not exist
long FileBytes(const string name)
  {
   if(!FileIsExist(name))
      return -1;
   int fh = FileOpen(name, FILE_READ | FILE_BIN | FILE_SHARE_READ | FILE_SHARE_WRITE);
   if(fh == INVALID_HANDLE)
      return -1;
   long n = (long)FileSize(fh);
   FileClose(fh);
   return n;
  }

//--- Opens the file for `day`. A new or empty file continues from the newest earlier file of
//--- this chain (seq < 0: look it up); a file that already holds events continues from itself.
bool OpenDay(const string day, const long seq, const string prev)
  {
   string name = g_prefix + day + ".jsonl";
   long s = seq;
   string h = prev;
   if(s < 0 && FileBytes(name) <= 0)
     {
      bool found = false;
      long lastSeq = 0;
      string lastHash = "";
      if(!VcpFindPrevious(g_prefix, ".jsonl", name, InpActorID, g_chain, found, lastSeq, lastHash))
        {
         Print("VCP: ", VcpLastError());
         return false;
        }
      s = found ? lastSeq + 1 : 0;
      h = found ? lastHash : "";
     }
   if(s < 0)
     {
      s = 0;   // the file holds events: Open continues from its last line
      h = "";
     }
   if(!g_writer.Open(name, InpActorID, g_chain, InpPolicyID, 3, InpPrevHash, s, h))
     {
      Print("VCP: ", VcpLastError());
      return false;
     }
   g_day = day;
   return true;
  }

int OnInit()
  {
   g_chain = InpActorID + "-" + IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN)) + "-" + IntegerToString(InpMagic);
   g_prefix = "vcp-" + SafeName(g_chain) + "-";
   if(!OpenDay(DayOf(TimeGMT()), -1, ""))
      return INIT_FAILED;
   if(g_writer.NextSequence() == 0)
     {
      CVcpJson *p = VcpObj();
      CVcpJson *gov = VcpObj();
      gov.Put("AlgoID", VcpStr(MQLInfoString(MQL_PROGRAM_NAME)));
      gov.Put("AlgoVersion", VcpStr(VCP_SDK_VERSION));
      p.Put("VCP-GOV", gov);
      if(g_writer.Write("INIT", p) == "")
         Print("VCP: write failed: ", VcpLastError());
     }
   return INIT_SUCCEEDED;
  }

void OnDeinit(const int reason)
  {
   g_writer.Close();
  }

//--- at the first event of a new UTC day, close the file and continue the chain in a new one
void RotateIfNeeded(void)
  {
   string day = DayOf(TimeGMT());
   if(day == g_day)
      return;
   long seq = g_writer.NextSequence();
   string prev = g_writer.LastHash();
   g_writer.Close();
   OpenDay(day, seq, prev);
  }

//--- decimal places of a symbol's volume step (0.01 -> 2)
int VolumeDigits(const string symbol)
  {
   double step = SymbolInfoDouble(symbol, SYMBOL_VOLUME_STEP);
   int d = 0;
   while(d < 8 && MathAbs(step * MathPow(10, d) - MathRound(step * MathPow(10, d))) > 1e-9)
      d++;
   return d;
  }

//--- rejectReason != "" adds VCP-TRADE.RejectReason and VCP-TRADE.ErrorDetails (INTERPRETATIONS.md I-7)
void Record(const string type, const string symbol, const ulong order, const ulong deal, const double price, const double volume,
            const string rejectReason = "")
  {
   RotateIfNeeded();
   int digits = (int)SymbolInfoInteger(symbol, SYMBOL_DIGITS);
   CVcpJson *p = VcpObj();
   CVcpJson *t = VcpObj();
   t.Put("Symbol", VcpStr(symbol));
   t.Put("OrderID", VcpStr(IntegerToString((long)order)));
   if(deal > 0)
      t.Put("DealID", VcpStr(IntegerToString((long)deal)));
   t.Put("Price", VcpStr(DoubleToString(price, digits)));              // decimal string, VCP v1.2 section 4.2.2
   t.Put("Quantity", VcpStr(DoubleToString(volume, VolumeDigits(symbol))));
   if(rejectReason != "")
     {
      t.Put("RejectReason", VcpStr(rejectReason));
      CVcpJson *ed = VcpObj();
      ed.Put("ErrorCode", VcpStr(rejectReason));
      ed.Put("ErrorMessage", VcpStr("order rejected (order state " + rejectReason + ")"));
      ed.Put("Severity", VcpStr("WARNING"));
      ed.Put("AffectedComponent", VcpStr("trade-server"));
      t.Put("ErrorDetails", ed);
     }
   p.Put("VCP-TRADE", t);
   if(g_writer.Write(type, p) == "")
      Print("VCP: write failed: ", VcpLastError());
  }

//--- the order's magic number, from the open orders or, if it has already left them, the history
bool OrderMagic(const ulong ticket, long &magic)
  {
   if(OrderSelect(ticket))
     {
      magic = OrderGetInteger(ORDER_MAGIC);
      return true;
     }
   if(HistoryOrderSelect(ticket))
     {
      magic = HistoryOrderGetInteger(ticket, ORDER_MAGIC);
      return true;
     }
   return false;
  }

void OnTradeTransaction(const MqlTradeTransaction &trans, const MqlTradeRequest &request, const MqlTradeResult &result)
  {
   long magic = 0;
   if(trans.type == TRADE_TRANSACTION_ORDER_ADD)
     {
      //--- a market order may already be in the history when this transaction is processed
      if(OrderMagic(trans.order, magic) && magic == InpMagic)
         Record("ORD", trans.symbol, trans.order, 0, trans.price, trans.volume);
      return;
     }
   if(trans.type == TRADE_TRANSACTION_DEAL_ADD)
     {
      if(HistoryDealSelect(trans.deal) && HistoryDealGetInteger(trans.deal, DEAL_MAGIC) == InpMagic)
         Record("EXE", trans.symbol, trans.order, trans.deal, trans.price, trans.volume);
      return;
     }
   if(trans.type == TRADE_TRANSACTION_HISTORY_ADD)
     {
      //--- an order moved to history: record cancellations, expiries and rejections (not fills)
      string evType = "";
      if(trans.order_state == ORDER_STATE_CANCELED || trans.order_state == ORDER_STATE_EXPIRED)
         evType = "CXL";
      else if(trans.order_state == ORDER_STATE_REJECTED)
         evType = "ERR_REJECT";
      if(evType != "" && HistoryOrderSelect(trans.order) && HistoryOrderGetInteger(trans.order, ORDER_MAGIC) == InpMagic)
         Record(evType, trans.symbol, trans.order, 0, trans.price, trans.volume,
                evType == "ERR_REJECT" ? "ORDER_STATE_REJECTED" : "");
     }
  }
//+------------------------------------------------------------------+
