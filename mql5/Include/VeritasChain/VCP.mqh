//+------------------------------------------------------------------+
//| VCP.mqh - VeritasChain Protocol (VCP) v1.2 event core for MQL5   |
//|                                                                  |
//| veritaschain/vcp-sdk 0.1.0 (pre-release, first-party, not         |
//| certified). Apache-2.0.                                           |
//|                                                                  |
//| What this file does inside MetaTrader 5:                         |
//|  - builds VCP Header/Payload objects and serialises them in the  |
//|    SDK's canonical form: RFC 8785 for strings, booleans, null,    |
//|    arrays and objects; integers as exact decimal digits (see      |
//|    INTERPRETATIONS.md I-4); no floating-point numbers - VCP v1.2  |
//|    requires financial values as decimal strings;                  |
//|  - computes the EventHash (SHA-256, VCP v1.2 section 6.1);         |
//|  - computes RFC 6962 Merkle roots and verifies inclusion proofs;  |
//|  - writes unsigned events as JSON Lines for the signing sidecar.  |
//|                                                                  |
//| What it does not do: MQL5 has no Ed25519, so events are signed    |
//| and batched outside the terminal, e.g. with the Python command    |
//|   vcp seal events.jsonl --private-key-file KEY --out ... ...     |
//| (see mql5/README.md). This file has not been compiled in this     |
//| repository's CI; run Scripts/VeritasChain/VCP_SelfTest.mq5.        |
//+------------------------------------------------------------------+
#define VCP_SDK_VERSION "0.1.0"
#define VCP_SPEC_VERSION "1.2.0"

#define VCP_JNULL 0
#define VCP_JBOOL 1
#define VCP_JINT  2
#define VCP_JSTR  3
#define VCP_JARR  4
#define VCP_JOBJ  5

string g_vcp_error = "";

string VcpLastError(void) { return g_vcp_error; }
void   VcpClearError(void) { g_vcp_error = ""; }

//--- UTF-16 code-unit order (RFC 8785 section 3.2.3)
bool VcpKeyLess(const string a, const string b)
  {
   int la = StringLen(a), lb = StringLen(b);
   int n = (la < lb) ? la : lb;
   for(int i = 0; i < n; i++)
     {
      ushort ca = StringGetCharacter(a, i);
      ushort cb = StringGetCharacter(b, i);
      if(ca != cb)
         return ca < cb;
     }
   return la < lb;
  }

//--- RFC 8785 string serialisation
string VcpJsonString(const string s)
  {
   string out = "\"";
   int n = StringLen(s);
   for(int i = 0; i < n; i++)
     {
      ushort c = StringGetCharacter(s, i);
      if(c >= 0xD800 && c <= 0xDBFF)
        {
         ushort d = (i + 1 < n) ? StringGetCharacter(s, i + 1) : (ushort)0;
         if(d < 0xDC00 || d > 0xDFFF)
           {
            g_vcp_error = "string contains a lone surrogate";
            return "";
           }
         out += StringSubstr(s, i, 2);
         i++;
         continue;
        }
      if(c >= 0xDC00 && c <= 0xDFFF)
        {
         g_vcp_error = "string contains a lone surrogate";
         return "";
        }
      if(c == 0x08)      out += "\\b";
      else if(c == 0x09) out += "\\t";
      else if(c == 0x0A) out += "\\n";
      else if(c == 0x0C) out += "\\f";
      else if(c == 0x0D) out += "\\r";
      else if(c == 0x22) out += "\\\"";
      else if(c == 0x5C) out += "\\\\";
      else if(c < 0x20)  out += StringFormat("\\u%04x", (int)c);
      else               out += StringSubstr(s, i, 1);
     }
   return out + "\"";
  }

//+------------------------------------------------------------------+
//| A JSON value. Objects own their children and delete them.        |
//+------------------------------------------------------------------+
class CVcpJson
  {
public:
   int               m_type;
   bool              m_bool;
   long              m_int;
   string            m_str;
   string            m_keys[];
   CVcpJson         *m_vals[];

                     CVcpJson(void) { m_type = VCP_JNULL; m_bool = false; m_int = 0; m_str = ""; }
                    ~CVcpJson(void)
     {
      int n = ArraySize(m_vals);
      for(int i = 0; i < n; i++)
         if(CheckPointer(m_vals[i]) == POINTER_DYNAMIC)
            delete m_vals[i];
     }

   //--- object member: replaces an existing key (and deletes the old value)
   CVcpJson         *Put(const string key, CVcpJson *value)
     {
      int n = ArraySize(m_keys);
      for(int i = 0; i < n; i++)
         if(m_keys[i] == key)
           {
            if(m_vals[i] != value && CheckPointer(m_vals[i]) == POINTER_DYNAMIC)
               delete m_vals[i];
            m_vals[i] = value;
            return GetPointer(this);
           }
      ArrayResize(m_keys, n + 1);
      ArrayResize(m_vals, n + 1);
      m_keys[n] = key;
      m_vals[n] = value;
      return GetPointer(this);
     }

   //--- array element
   CVcpJson         *Add(CVcpJson *value)
     {
      int n = ArraySize(m_vals);
      ArrayResize(m_vals, n + 1);
      m_vals[n] = value;
      return GetPointer(this);
     }

   CVcpJson         *Get(const string key)
     {
      int n = ArraySize(m_keys);
      for(int i = 0; i < n; i++)
         if(m_keys[i] == key)
            return m_vals[i];
      return NULL;
     }

   //--- Canonical form. Returns "" and sets VcpLastError() if a string holds a lone surrogate.
   string            Canonical(void)
     {
      VcpClearError();
      string r = CanonicalPart();
      return (g_vcp_error != "") ? "" : r;
     }

   string            CanonicalPart(void)
     {
      if(m_type == VCP_JNULL) return "null";
      if(m_type == VCP_JBOOL) return m_bool ? "true" : "false";
      if(m_type == VCP_JINT)  return IntegerToString(m_int);
      if(m_type == VCP_JSTR)  return VcpJsonString(m_str);
      string out;
      int n = ArraySize(m_vals);
      if(m_type == VCP_JARR)
        {
         out = "[";
         for(int i = 0; i < n; i++)
           {
            if(i > 0) out += ",";
            out += m_vals[i].CanonicalPart();
           }
         return out + "]";
        }
      //--- object: insertion sort of indices by UTF-16 key order
      int idx[];
      ArrayResize(idx, n);
      for(int i = 0; i < n; i++) idx[i] = i;
      for(int i = 1; i < n; i++)
        {
         int v = idx[i];
         int j = i - 1;
         while(j >= 0 && VcpKeyLess(m_keys[v], m_keys[idx[j]]))
           {
            idx[j + 1] = idx[j];
            j--;
           }
         idx[j + 1] = v;
        }
      out = "{";
      for(int i = 0; i < n; i++)
        {
         if(i > 0) out += ",";
         out += VcpJsonString(m_keys[idx[i]]) + ":" + m_vals[idx[i]].CanonicalPart();
        }
      return out + "}";
     }
  };

CVcpJson *VcpNull(void)            { CVcpJson *j = new CVcpJson(); return j; }
CVcpJson *VcpBool(const bool v)    { CVcpJson *j = new CVcpJson(); j.m_type = VCP_JBOOL; j.m_bool = v; return j; }
CVcpJson *VcpInt(const long v)     { CVcpJson *j = new CVcpJson(); j.m_type = VCP_JINT; j.m_int = v; return j; }
CVcpJson *VcpStr(const string v)   { CVcpJson *j = new CVcpJson(); j.m_type = VCP_JSTR; j.m_str = v; return j; }
CVcpJson *VcpObj(void)             { CVcpJson *j = new CVcpJson(); j.m_type = VCP_JOBJ; return j; }
CVcpJson *VcpArr(void)             { CVcpJson *j = new CVcpJson(); j.m_type = VCP_JARR; return j; }

//+------------------------------------------------------------------+
//| Bytes, hex, SHA-256                                              |
//+------------------------------------------------------------------+
int VcpUtf8(const string s, uchar &out[])
  {
   ArrayResize(out, 0);
   if(StringLen(s) == 0)
      return 0;
   int n = StringToCharArray(s, out, 0, -1, CP_UTF8);   // includes the terminating zero
   if(n > 0 && out[n - 1] == 0)
      n--;
   ArrayResize(out, n);
   return n;
  }

string VcpHex(const uchar &b[])
  {
   string s = "";
   int n = ArraySize(b);
   for(int i = 0; i < n; i++)
      s += StringFormat("%02x", (int)b[i]);
   return s;
  }

int VcpHexNibble(const ushort c)
  {
   if(c >= '0' && c <= '9') return c - '0';
   if(c >= 'a' && c <= 'f') return c - 'a' + 10;
   if(c >= 'A' && c <= 'F') return c - 'A' + 10;
   return -1;
  }

bool VcpUnhex(const string h, uchar &out[])
  {
   int n = StringLen(h);
   if(n % 2 != 0) return false;
   ArrayResize(out, n / 2);
   for(int i = 0; i < n / 2; i++)
     {
      int hi = VcpHexNibble(StringGetCharacter(h, 2 * i));
      int lo = VcpHexNibble(StringGetCharacter(h, 2 * i + 1));
      if(hi < 0 || lo < 0) return false;
      out[i] = (uchar)(hi * 16 + lo);
     }
   return true;
  }

bool VcpSha256(const uchar &data[], uchar &out[])
  {
   uchar key[];
   ArrayResize(key, 0);
   int r = CryptEncode(CRYPT_HASH_SHA256, data, key, out);
   return r == 32;
  }

//--- bare lowercase hex from "<hex>" or "sha256:<hex>"; "" if malformed
string VcpParseHash(const string v)
  {
   string body = v;
   if(StringFind(v, "sha256:") == 0)
      body = StringSubstr(v, 7);
   if(StringLen(body) != 64) return "";
   uchar tmp[];
   if(!VcpUnhex(body, tmp)) return "";
   StringToLower(body);
   return body;
  }

//+------------------------------------------------------------------+
//| EventHash = SHA-256( JCS(Header) + JCS(Payload) [+ PrevHash hex] ) |
//+------------------------------------------------------------------+
string VcpEventHash(CVcpJson *header, CVcpJson *payload, const string prevHash = "")
  {
   string hc = header.Canonical();
   if(g_vcp_error != "")
      return "";
   string pc = payload.Canonical();
   if(g_vcp_error != "")
      return "";
   string src = hc + pc;
   if(prevHash != "")
     {
      string p = VcpParseHash(prevHash);
      if(p == "")
        {
         g_vcp_error = "malformed PrevHash";
         return "";
        }
      if(p != "0000000000000000000000000000000000000000000000000000000000000000")
         src += p;
     }
   uchar data[], digest[];
   VcpUtf8(src, data);
   if(!VcpSha256(data, digest))
     {
      g_vcp_error = "SHA-256 failed";
      return "";
     }
   return VcpHex(digest);
  }

//+------------------------------------------------------------------+
//| RFC 6962 / RFC 9162 Merkle tree over decoded 32-byte EventHashes |
//+------------------------------------------------------------------+
void VcpLeafHash(const uchar &flat[], const int offset, uchar &out[])
  {
   uchar buf[];
   ArrayResize(buf, 33);
   buf[0] = 0;
   ArrayCopy(buf, flat, 1, offset, 32);
   VcpSha256(buf, out);
  }

void VcpNodeHash(const uchar &l[], const uchar &r[], uchar &out[])
  {
   uchar buf[];
   ArrayResize(buf, 65);
   buf[0] = 1;
   ArrayCopy(buf, l, 1, 0, 32);
   ArrayCopy(buf, r, 33, 0, 32);
   VcpSha256(buf, out);
  }

int VcpSplit(const int n)
  {
   int k = 1;
   while(k * 2 < n) k *= 2;
   return k;
  }

void VcpMth(const uchar &flat[], const int lo, const int hi, uchar &out[])
  {
   int n = hi - lo;
   if(n == 1)
     {
      VcpLeafHash(flat, lo * 32, out);
      return;
     }
   int k = VcpSplit(n);
   uchar left[], right[];
   VcpMth(flat, lo, lo + k, left);
   VcpMth(flat, lo + k, hi, right);
   VcpNodeHash(left, right, out);
  }

//--- root (bare hex) of the EventHash values in order; "" on error. Needs at least one hash.
string VcpMerkleRoot(const string &eventHashes[])
  {
   int n = ArraySize(eventHashes);
   if(n < 1) return "";
   uchar flat[];
   ArrayResize(flat, n * 32);
   for(int i = 0; i < n; i++)
     {
      uchar one[];
      string h = VcpParseHash(eventHashes[i]);
      if(h == "" || !VcpUnhex(h, one)) return "";
      ArrayCopy(flat, one, i * 32, 0, 32);
     }
   uchar root[];
   VcpMth(flat, 0, n, root);
   return VcpHex(root);
  }

//--- RFC 9162 section 2.1.3.2
bool VcpVerifyInclusion(const string eventHash, const long index, const long treeSize,
                        const string &proof[], const string expectedRoot)
  {
   if(index < 0 || treeSize <= 0 || index >= treeSize) return false;
   uchar leaf[], r[], expected[];
   string lh = VcpParseHash(eventHash), rh = VcpParseHash(expectedRoot);
   if(lh == "" || rh == "" || !VcpUnhex(lh, leaf) || !VcpUnhex(rh, expected)) return false;
   VcpLeafHash(leaf, 0, r);
   ulong fn = (ulong)index, sn = (ulong)(treeSize - 1);
   int m = ArraySize(proof);
   for(int i = 0; i < m; i++)
     {
      uchar p[], t[];
      string ph = VcpParseHash(proof[i]);
      if(ph == "" || !VcpUnhex(ph, p)) return false;
      if(sn == 0) return false;
      if((fn & 1) == 1 || fn == sn)
        {
         VcpNodeHash(p, r, t);
         if((fn & 1) == 0)
            while((fn & 1) == 0 && fn != 0)
              {
               fn >>= 1;
               sn >>= 1;
              }
        }
      else
         VcpNodeHash(r, p, t);
      ArrayCopy(r, t, 0, 0, 32);
      fn >>= 1;
      sn >>= 1;
     }
   return sn == 0 && VcpHex(r) == VcpHex(expected);
  }

//+------------------------------------------------------------------+
//| Time and identifiers                                             |
//+------------------------------------------------------------------+
long  g_vcp_base_us = 0;
ulong g_vcp_base_tick = 0;
long  g_vcp_last_ns = 0;
long  g_vcp_uuid_counter = 0;

//--- Align a microsecond counter to TimeGMT() at a second boundary (waits up to about 1 s).
//--- Accuracy is best-effort: ClockSyncStatus BEST_EFFORT (VCP v1.2 section 1.5.3).
void VcpClockInit(void)
  {
   datetime t0 = TimeGMT();
   ulong start = GetMicrosecondCount();
   while(TimeGMT() == t0 && GetMicrosecondCount() - start < 1100000) { }
   g_vcp_base_tick = GetMicrosecondCount();
   g_vcp_base_us = (long)TimeGMT() * 1000000;
  }

//--- Current time in nanoseconds since the Unix epoch, never earlier than the previous
//--- value returned (so TimestampInt and UUIDv7 order follow the call order). If the counter
//--- drifts from TimeGMT() by more than 2 s it is re-based to the current whole TimeGMT()
//--- second without waiting; after a backwards re-base the value holds until the clock
//--- catches up. In the Strategy Tester this is the simulated TimeGMT() at one-second
//--- resolution; pass explicit timestamps there if needed.
long VcpNowNs(void)
  {
   long ns;
   if(MQLInfoInteger(MQL_TESTER))
      ns = (long)TimeGMT() * 1000000000;
   else
     {
      if(g_vcp_base_us == 0) VcpClockInit();
      long us = g_vcp_base_us + (long)(GetMicrosecondCount() - g_vcp_base_tick);
      long gmt = (long)TimeGMT();
      if(us / 1000000 > gmt + 2 || us / 1000000 < gmt - 2)
        {
         g_vcp_base_tick = GetMicrosecondCount();
         g_vcp_base_us = gmt * 1000000;
         us = g_vcp_base_us;
        }
      ns = us * 1000;
     }
   if(ns < g_vcp_last_ns)
      ns = g_vcp_last_ns;
   g_vcp_last_ns = ns;
   return ns;
  }

//--- RFC 3339 UTC with 3, 6 or 9 fractional digits (0 is also accepted: whole seconds).
//--- Returns "" and sets VcpLastError() for a negative time or another digit count.
string VcpIsoFromNs(const long ns, const int digits = 3)
  {
   if(ns < 0 || (digits != 0 && digits != 3 && digits != 6 && digits != 9))
     {
      g_vcp_error = "VcpIsoFromNs: negative time or digits not 0, 3, 6 or 9";
      return "";
     }
   long sec = ns / 1000000000;
   long frac = ns % 1000000000;
   MqlDateTime t;
   TimeToStruct((datetime)sec, t);
   string s = StringFormat("%04d-%02d-%02dT%02d:%02d:%02d", t.year, t.mon, t.day, t.hour, t.min, t.sec);
   if(digits > 0)
      s += "." + StringSubstr(IntegerToString(frac, 9, '0'), 0, digits);
   return s + "Z";
  }

//--- RFC 9562 UUIDv7. The random bits come from SHA-256 over time, a counter, the chart
//--- and account identifiers and MathRand(): unique in practice, not cryptographically random.
string VcpUuid7(const long unixMs)
  {
   if(g_vcp_uuid_counter == 0)
      MathSrand((uint)(GetMicrosecondCount() ^ (ulong)ChartID() ^ (ulong)AccountInfoInteger(ACCOUNT_LOGIN)));
   g_vcp_uuid_counter++;
   uchar seed[], rnd[];
   VcpUtf8(StringFormat("%I64d|%I64d|%I64u|%I64d|%I64d|%d|%d", unixMs, g_vcp_uuid_counter, GetMicrosecondCount(),
                        ChartID(), AccountInfoInteger(ACCOUNT_LOGIN), MathRand(), MathRand()), seed);
   VcpSha256(seed, rnd);
   uchar b[];
   ArrayResize(b, 16);
   for(int i = 0; i < 6; i++)
      b[i] = (uchar)((unixMs >> (8 * (5 - i))) & 0xFF);
   for(int i = 0; i < 10; i++)
      b[6 + i] = rnd[i];
   b[6] = (uchar)(0x70 | (b[6] & 0x0F));
   b[8] = (uchar)(0x80 | (b[8] & 0x3F));
   string h = VcpHex(b);
   return StringSubstr(h, 0, 8) + "-" + StringSubstr(h, 8, 4) + "-" + StringSubstr(h, 12, 4) + "-" +
          StringSubstr(h, 16, 4) + "-" + StringSubstr(h, 20, 12);
  }

//--- A VCP v1.2 Header. eventId "" generates a UUIDv7.
CVcpJson *VcpHeader(const string eventType, const string actorId, const string chainId, const long sequenceNum,
                    const string policyId, const long timestampNs, const int precisionDigits = 3, const string eventId = "")
  {
   CVcpJson *h = VcpObj();
   h.Put("EventID", VcpStr(eventId == "" ? VcpUuid7(timestampNs / 1000000) : eventId));
   h.Put("TimestampISO", VcpStr(VcpIsoFromNs(timestampNs, precisionDigits)));
   h.Put("TimestampInt", VcpInt(timestampNs));
   h.Put("EventType", VcpStr(eventType));
   h.Put("ActorID", VcpStr(actorId));
   h.Put("ChainID", VcpStr(chainId));
   h.Put("SequenceNum", VcpInt(sequenceNum));
   h.Put("PolicyID", VcpStr(policyId));
   return h;
  }

//+------------------------------------------------------------------+
//| Reading back what CVcpWriter wrote                               |
//+------------------------------------------------------------------+
//--- The last line of an open binary file, without its line ending. Returns 1 when `line` was
//--- read, 0 when the file holds no line, and -1 with VcpLastError() set on a read error or
//--- when the file does not end with "\n" (its last line is incomplete).
int VcpReadLastLine(const int handle, string &line)
  {
   line = "";
   ulong size = FileSize(handle);
   if(size == 0)
      return 0;
   ulong chunk = 65536;
   while(true)
     {
      if(chunk > size)
         chunk = size;
      uchar buf[];
      ArrayResize(buf, (int)chunk);
      if(!FileSeek(handle, (long)(size - chunk), SEEK_SET))
        {
         g_vcp_error = "FileSeek failed: " + IntegerToString(GetLastError());
         return -1;
        }
      uint got = FileReadArray(handle, buf, 0, (int)chunk);
      if(got != (uint)chunk)
        {
         g_vcp_error = "FileReadArray failed: " + IntegerToString(GetLastError());
         return -1;
        }
      int n = (int)chunk;
      if(buf[n - 1] != '\n')
        {
         g_vcp_error = "the file does not end with a newline: its last line is incomplete";
         return -1;
        }
      int end = n;
      while(end > 0 && (buf[end - 1] == '\n' || buf[end - 1] == '\r'))
         end--;
      if(end == 0 && chunk == size)
         return 0;
      int start = end;
      while(start > 0 && buf[start - 1] != '\n')
         start--;
      if(end > 0 && (start > 0 || chunk == size))
        {
         line = CharArrayToString(buf, start, end - start, CP_UTF8);
         return 1;
        }
      if(chunk >= 16777216)
        {
         g_vcp_error = "the last line is longer than 16 MB";
         return -1;
        }
      chunk *= 4;
     }
   return -1;
  }

//--- SequenceNum and EventHash (bare hex) of a line CVcpWriter wrote for this ActorID and
//--- ChainID. The line must start with the canonical Header of that chain and end with the
//--- writer's Security object; anything else is refused with VcpLastError() set.
bool VcpParseOwnLine(const string line, const string actorId, const string chainId, long &seq, string &hash)
  {
   string head = "{\"Header\":{\"ActorID\":" + VcpJsonString(actorId) + ",\"ChainID\":" + VcpJsonString(chainId) + ",\"EventID\":";
   if(StringFind(line, head) != 0)
     {
      g_vcp_error = "the last line is not an event of ActorID " + actorId + " and ChainID " + chainId;
      return false;
     }
   //--- canonical Header order: ActorID ChainID EventID EventType PolicyID SequenceNum TimestampISO TimestampInt.
   //--- String values cannot contain an unescaped quote, so the first match is the Header's key.
   string sk = ",\"SequenceNum\":";
   int p = StringFind(line, sk, StringLen(head));
   if(p < 0)
     {
      g_vcp_error = "the last line has no Header.SequenceNum";
      return false;
     }
   p += StringLen(sk);
   int q = p;
   while(q < StringLen(line) && StringGetCharacter(line, q) >= '0' && StringGetCharacter(line, q) <= '9')
      q++;
   if(q == p || q - p > 18 || StringFind(line, ",\"TimestampISO\":", q) != q)
     {
      g_vcp_error = "the last line's SequenceNum is not in the writer's format";
      return false;
     }
   //--- Security sorts last and holds only strings, so its EventHash is the last such key.
   string hk = "\"Security\":{\"EventHash\":\"sha256:";
   int r = -1;
   int f = StringFind(line, hk);
   while(f >= 0)
     {
      r = f;
      f = StringFind(line, hk, f + 1);
     }
   string h = (r < 0) ? "" : VcpParseHash(StringSubstr(line, r + StringLen(hk), 64));
   if(h == "")
     {
      g_vcp_error = "the last line has no Security.EventHash";
      return false;
     }
   string tail = StringSubstr(line, r + StringLen(hk) + 64);
   string plain = "\",\"HashAlgo\":\"SHA256\"}}";
   string linked = "\",\"HashAlgo\":\"SHA256\",\"PrevHash\":\"sha256:";
   bool ok = (tail == plain);
   if(!ok && StringFind(tail, linked) == 0 && StringLen(tail) == StringLen(linked) + 64 + 3)
      ok = VcpParseHash(StringSubstr(tail, StringLen(linked), 64)) != "" && StringSubstr(tail, StringLen(linked) + 64) == "\"}}";
   if(!ok)
     {
      g_vcp_error = "the last line's Security object is not in the writer's format";
      return false;
     }
   seq = StringToInteger(StringSubstr(line, p, q - p));
   hash = h;
   return true;
  }

//--- Where a new file of a chain continues from: the last event of the newest non-empty file
//--- named prefix + YYYYMMDD + suffix that sorts before `before`. Returns false with
//--- VcpLastError() set if such a file cannot be read or its last line is not an event of this
//--- chain; found is false when there is no earlier event.
bool VcpFindPrevious(const string prefix, const string suffix, const string before, const string actorId,
                     const string chainId, bool &found, long &lastSeq, string &lastHash)
  {
   found = false;
   string names[];
   string name;
   long sh = FileFindFirst(prefix + "*" + suffix, name);
   if(sh != INVALID_HANDLE)
     {
      do
        {
         bool dated = StringLen(name) == StringLen(prefix) + 8 + StringLen(suffix);
         for(int i = 0; dated && i < 8; i++)
           {
            ushort c = StringGetCharacter(name, StringLen(prefix) + i);
            dated = (c >= '0' && c <= '9');
           }
         if(dated && StringCompare(name, before) < 0)
           {
            int k = ArraySize(names);
            ArrayResize(names, k + 1);
            names[k] = name;
           }
        }
      while(FileFindNext(sh, name));
      FileFindClose(sh);
     }
   //--- newest first
   int n = ArraySize(names);
   for(int i = 1; i < n; i++)
     {
      string key = names[i];
      int j = i - 1;
      while(j >= 0 && StringCompare(names[j], key) < 0)
        {
         names[j + 1] = names[j];
         j--;
        }
      names[j + 1] = key;
     }
   for(int i = 0; i < n; i++)
     {
      int h = FileOpen(names[i], FILE_READ | FILE_BIN | FILE_SHARE_READ | FILE_SHARE_WRITE);
      if(h == INVALID_HANDLE)
        {
         g_vcp_error = names[i] + ": FileOpen failed: " + IntegerToString(GetLastError());
         return false;
        }
      string line;
      int r = VcpReadLastLine(h, line);
      FileClose(h);
      if(r == 0)
         continue;
      if(r < 0 || !VcpParseOwnLine(line, actorId, chainId, lastSeq, lastHash))
        {
         g_vcp_error = names[i] + ": " + g_vcp_error;
         return false;
        }
      found = true;
      return true;
     }
   return true;
  }

//+------------------------------------------------------------------+
//| Writes unsigned events as JSON Lines (UTF-8, "\n") for           |
//| `vcp seal`. Each line: {"Header":...,"Payload":...,"Security":   |
//| {"EventHash":"sha256:...","HashAlgo":"SHA256"[,"PrevHash":...]}} |
//| The sidecar recomputes the hash and refuses lines whose hash     |
//| differs. One file holds one ActorID/ChainID.                     |
//+------------------------------------------------------------------+
class CVcpWriter
  {
private:
   int               m_handle;
   string            m_actor;
   string            m_chain;
   string            m_policy;
   long              m_seq;
   int               m_digits;
   bool              m_chainHashes;
   string            m_last;
   bool              m_broken;

public:
                     CVcpWriter(void) { m_handle = INVALID_HANDLE; m_seq = 0; m_digits = 3; m_chainHashes = false; m_last = ""; m_broken = false; }

   void              Close(void)
     {
      if(m_handle != INVALID_HANDLE)
        {
         FileClose(m_handle);
         m_handle = INVALID_HANDLE;
        }
     }

                    ~CVcpWriter(void) { Close(); }

   //--- Opens fileName in MQL5/Files (creating it if needed) to append events of one ActorID/ChainID.
   //--- If the file holds events, SequenceNum and the hash chain continue from its last line and
   //--- startSequence/prevHash are ignored. If it holds none, the chain starts at startSequence,
   //--- linked to prevHash ("" for none): pass the previous file's last SequenceNum + 1 and
   //--- EventHash to continue a chain in a new file. Returns false with VcpLastError() set, without
   //--- modifying the file, if its last line is incomplete or is not an event of this chain.
   bool              Open(const string fileName, const string actorId, const string chainId, const string policyId,
                          const int precisionDigits = 3, const bool usePrevHash = false,
                          const long startSequence = 0, const string prevHash = "")
     {
      Close();
      VcpClearError();
      m_actor = actorId;
      m_chain = chainId;
      m_policy = policyId;
      m_digits = precisionDigits;
      m_chainHashes = usePrevHash;
      m_seq = startSequence;
      m_last = "";
      m_broken = false;
      if(startSequence < 0)
        {
         g_vcp_error = "startSequence is negative";
         return false;
        }
      if(prevHash != "")
        {
         m_last = VcpParseHash(prevHash);
         if(m_last == "")
           {
            g_vcp_error = "prevHash is not a 32-byte hex digest";
            return false;
           }
        }
      m_handle = FileOpen(fileName, FILE_READ | FILE_WRITE | FILE_BIN | FILE_SHARE_READ);
      if(m_handle == INVALID_HANDLE)
        {
         g_vcp_error = fileName + ": FileOpen failed: " + IntegerToString(GetLastError());
         return false;
        }
      string line;
      int r = VcpReadLastLine(m_handle, line);
      if(r == 1)
        {
         long seq = 0;
         string h = "";
         if(VcpParseOwnLine(line, m_actor, m_chain, seq, h))
           {
            m_seq = seq + 1;
            m_last = h;
           }
         else
            r = -1;
        }
      if(r < 0)
        {
         g_vcp_error = fileName + ": " + g_vcp_error;
         Close();
         return false;
        }
      FileSeek(m_handle, 0, SEEK_END);
      return true;
     }

   long              NextSequence(void) const { return m_seq; }

   //--- EventHash (bare hex) of the last event written or resumed; "" if none.
   string            LastHash(void) const { return m_last; }

   //--- Writes one event and deletes payload. Returns the EventHash (bare hex) or "".
   //--- On failure nothing advances, so the next event links to the last one written.
   //--- After a short write the writer refuses further writes: the file may end with a
   //--- partial line, which must be removed before the file is opened again.
   string            Write(const string eventType, CVcpJson *payload, const long timestampNs = 0, const string eventId = "")
     {
      if(m_handle == INVALID_HANDLE || m_broken)
        {
         g_vcp_error = m_broken ? "a previous write was incomplete; repair the file and reopen it" : "writer is not open";
         delete payload;
         return "";
        }
      long ts = (timestampNs == 0) ? VcpNowNs() : timestampNs;
      VcpClearError();
      CVcpJson *header = VcpHeader(eventType, m_actor, m_chain, m_seq, m_policy, ts, m_digits, eventId);
      if(g_vcp_error != "")
        {
         delete header;
         delete payload;
         return "";
        }
      string prev = (m_chainHashes && m_last != "") ? m_last : "";
      string h = VcpEventHash(header, payload, prev);
      if(h == "")
        {
         delete header;
         delete payload;
         return "";
        }
      CVcpJson *sec = VcpObj();
      sec.Put("EventHash", VcpStr("sha256:" + h));
      sec.Put("HashAlgo", VcpStr("SHA256"));
      if(prev != "")
         sec.Put("PrevHash", VcpStr("sha256:" + prev));
      CVcpJson *line = VcpObj();
      line.Put("Header", header);
      line.Put("Payload", payload);
      line.Put("Security", sec);
      string text = line.Canonical();
      delete line;   // deletes header, payload and sec
      if(text == "")
         return "";
      uchar bytes[];
      int len = VcpUtf8(text + "\n", bytes);
      uint written = FileWriteArray(m_handle, bytes, 0, len);
      FileFlush(m_handle);
      if(written != (uint)len)
        {
         m_broken = (written > 0);
         g_vcp_error = StringFormat("FileWriteArray wrote %u of %d bytes (error %d)", written, len, GetLastError());
         return "";
        }
      m_seq++;
      m_last = h;
      return h;
     }
  };
//+------------------------------------------------------------------+
