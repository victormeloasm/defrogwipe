// defrogwipe.cpp — Libertas Per Croack (Sapo + Ondaluna)
// AVISO: ESTE PROGRAMA APAGA DADOS. USE COM CUIDADO.
//
// Builds sugeridos (clang + lld):
// 1) Mínimo (menor binário):
//   clang++ -std=c++23 -Oz -DNDEBUG -D_FILE_OFFSET_BITS=64 -pipe \
//     -fvisibility=hidden -ffunction-sections -fdata-sections \
//     -fstack-protector-strong -fPIE -fno-plt -flto=thin -fuse-ld=lld \
//     -Wl,--gc-sections -Wl,--icf=all -Wl,-s -Wl,-O2 -Wl,--as-needed \
//     -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie \
//     -pthread defrogwipe.cpp -lsodium -o defrogwipe
//
// 2) Completo (NVMe + SCSI sanitize; precisa headers do sg):
//   clang++ -std=c++23 -Oz -DNDEBUG -D_FILE_OFFSET_BITS=64 -pipe \
//     -DUSE_LIBNVME -DUSE_SG_IO \
//     -fvisibility=hidden -ffunction-sections -fdata-sections \
//     -fstack-protector-strong -fPIE -fno-plt -flto=thin -fuse-ld=lld \
//     -Wl,--gc-sections -Wl,--icf=all -Wl,-s -Wl,-O2 -Wl,--as-needed \
//     -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie \
//     -pthread defrogwipe.cpp -lsodium -o defrogwipe

// C++ std
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cctype>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <algorithm>
#include <filesystem>
#include <random>
#include <stdexcept>

// POSIX / Linux
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>   // TIOCGWINSZ, ioctls de bloco
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/fs.h>    // BLKGETSIZE64, BLKSSZGET, BLKDISCARD, BLKZEROOUT
// #include <termios.h>  // (opcional; para TIOCGWINSZ basta <sys/ioctl.h>)

// Cripto/memória segura
#include <sodium.h>
#include <inttypes.h>

// NVMe / SCSI (opcionais, se você compilar com -DUSE_LIBNVME / -DUSE_SG_IO)
#if defined(USE_LIBNVME)
  #include <linux/nvme_ioctl.h>
  #include <linux/types.h>
#endif
#if defined(USE_SG_IO)
  #include <scsi/sg.h>
  #include <scsi/scsi.h>
#endif


using namespace std::chrono_literals;

// ===== Cores & logging =====
namespace Colors {
    constexpr const char* Reset   = "\x1b[0m";
    constexpr const char* Red     = "\x1b[31m";
    constexpr const char* Green   = "\x1b[32m";
    constexpr const char* Yellow  = "\x1b[33m";
    constexpr const char* Blue    = "\x1b[34m";
    constexpr const char* Magenta = "\x1b[35m";
    constexpr const char* Cyan    = "\x1b[36m";
}
static void note(const char* tag, const char* color, const char* fmt, ...) {
    std::fprintf(stderr, "%s[%s]%s ", color, tag, Colors::Reset);
    va_list ap; va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
}

// ===== Util =====
static std::atomic<bool> stop_flag{false};

static void on_termination(int sig) {
    stop_flag.store(true, std::memory_order_relaxed);
    note("signal", Colors::Yellow, "Recebido sinal %d. Finalizando…", sig);
    std::this_thread::sleep_for(100ms);
}
static double sec_since(const std::chrono::high_resolution_clock::time_point& t0) {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(now - t0).count();
}
static std::string format_eta(double sec) {
    if (sec < 0) sec = 0;
    int s = (int)(sec + 0.5);
    int h = s / 3600; s %= 3600;
    int m = s / 60;   s %= 60;
    char buf[64]; std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, s);
    return buf;
}
static std::string hex(const unsigned char* p, size_t n){
    static const char* H="0123456789abcdef";
    std::string out; out.resize(n*2);
    for(size_t i=0;i<n;i++){ out[2*i]=H[(p[i]>>4)&0xF]; out[2*i+1]=H[p[i]&0xF]; }
    return out;
}
static std::string basename_of(const std::string& path) {
    auto p = std::filesystem::path(path);
    return p.filename().string();
}
static std::string trim_ws(std::string s){
    auto isws=[](char c){ return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\f'; };
    while(!s.empty() && isws(s.front())) s.erase(s.begin());
    while(!s.empty() && isws(s.back())) s.pop_back();
    return s;
}
static bool read_file_u64(const std::string& path, uint64_t& out){
    FILE* f = std::fopen(path.c_str(), "r");
    if(!f) return false;
    char buf[128]; if(!std::fgets(buf,sizeof(buf),f)){ std::fclose(f); return false; }
    std::fclose(f);
    char* end=nullptr; errno=0;
    unsigned long long v = std::strtoull(buf, &end, 10);
    if(errno!=0) return false;
    out = (uint64_t)v; return true;
}
static std::string read_file_str(const std::string& path){
    FILE* f = std::fopen(path.c_str(), "r");
    if(!f) return {};
    char buf[512]; size_t n = std::fread(buf,1,sizeof(buf),f);
    std::fclose(f);
    return trim_ws(std::string(buf, buf + n));
}

// ===== RAII FD =====
class ScopedFD {
    int fd_{-1};
public:
    ScopedFD() = default;
    ScopedFD(const std::string& path, int flags) { fd_ = ::open(path.c_str(), flags); }
    explicit ScopedFD(int fd) : fd_(fd) {}
    ~ScopedFD(){ if (fd_ >= 0) ::close(fd_); }
    bool is_open() const { return fd_ >= 0; }
    int  get() const { return fd_; }
    operator int() const { return fd_; }
    ScopedFD(const ScopedFD&) = delete;
    ScopedFD& operator=(const ScopedFD&) = delete;
    ScopedFD(ScopedFD&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    ScopedFD& operator=(ScopedFD&& o) noexcept { if(this!=&o){ if(fd_>=0) ::close(fd_); fd_=o.fd_; o.fd_=-1; } return *this; }
};

// ===== Buffers =====
struct AlignedBuf {
    void*  p{nullptr};
    size_t sz{0};
    bool   locked{false};

    AlignedBuf() noexcept = default; // <<< CONSTRUTOR DEFAULT (corrige "no matching constructor")

    bool alloc(size_t size, size_t align) {
        if (size==0) return false;
        sz = size;
        if (align < 4096) align = 4096;
        if (posix_memalign(&p, align, sz) != 0) { p = nullptr; return false; }
        if (sodium_init() < 0) return false;
        if (sodium_mlock(p, sz) == 0) locked = true;
        return true;
    }
    unsigned char* data() {
        if(!p) throw std::runtime_error("AlignedBuf não alocado");
        return (unsigned char*)p;
    }
    size_t size() const { return sz; }
    ~AlignedBuf() {
        if (p) {
            sodium_memzero(p, sz);
            if (locked) sodium_munlock(p, sz);
            free(p);
        }
    }
    AlignedBuf(const AlignedBuf&) = delete;
    AlignedBuf& operator=(const AlignedBuf&) = delete;
};

struct SecureBuf {
    unsigned char* p{nullptr};
    size_t sz{0};
    bool alloc(size_t size){
        if(size==0) return false;
        if (sodium_init() < 0) return false;
        p=(unsigned char*)sodium_malloc(size); if(!p) return false;
        sz=size; return true;
    }
    SecureBuf()=default;
    explicit SecureBuf(size_t size){ if(!alloc(size)) throw std::bad_alloc(); }
    unsigned char* data(){
        if(!p) throw std::runtime_error("SecureBuf não inicializado");
        return p;
    }
    size_t size() const { return sz; }
    ~SecureBuf(){
        if(p){
            sodium_memzero(p, sz);
            sodium_free(p);
            p=nullptr; sz=0;
        }
    }
    SecureBuf(const SecureBuf&)=delete;
    SecureBuf& operator=(const SecureBuf&)=delete;
};

// ===== I/O =====
enum class SyncMode { Auto, Direct, ODSync, None };

static ssize_t pwrite_all(int fd, const void* buf, size_t n, uint64_t off) {
    const unsigned char* p = (const unsigned char*)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = ::pwrite(fd, p, left, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            note("pwrite", Colors::Red, "Erro em offset %" PRIu64 " (%s)", (uint64_t)off, std::strerror(errno));
            return r;
        }
        if (r == 0) break;
        left -= (size_t)r;
        p    += (size_t)r;
        off  += (uint64_t)r;
    }
    return (ssize_t)(n - left);
}
static int pread_all(int fd, void* buf, size_t n, uint64_t off) {
    unsigned char* p=(unsigned char*)buf;
    size_t left=n;
    while(left>0){
        ssize_t r=::pread(fd,p,left,(off_t)off);
        if(r<0){ if(errno==EINTR) continue; return -1; }
        if(r==0) break;
        left -= (size_t)r; p += (size_t)r; off += (uint64_t)r;
    }
    return (int)(n-left);
}
static bool check_device_writable(int fd) {
#ifdef BLKROGET
    int readonly = 0;
    if (ioctl(fd, BLKROGET, &readonly) == 0 && readonly) {
        note("device", Colors::Red, "Dispositivo em modo somente leitura");
        return false;
    }
#endif
    return true;
}

// ===== Fill helpers =====
static void fill_byte(unsigned char* p, size_t n, unsigned char b) { std::memset(p, b, n); }
static void fill_random(unsigned char* p, size_t n) { randombytes_buf(p, n); }

// ===== Progress (1 linha) + spinner + /proc/diskstats =====
struct Progress {
    std::atomic<uint32_t> active{0};
    std::atomic<uint64_t> bytes{0};
};

static bool tty_progress = false;

static bool stderr_is_tty() { return ::isatty(::fileno(stderr)); }
static int term_cols() {
    struct winsize ws{};
    if (::ioctl(::fileno(stderr), TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
    return 0;
}
static char spinner_next() {
    static const char seq[4] = {'|','/','-','\\'};
    static std::atomic<unsigned> idx{0};
    return seq[(idx++) & 3];
}
static void progress_begin() {
    if (stderr_is_tty()) {
        std::fprintf(stderr, "\x1b[?25l");
        tty_progress = true;
    }
}
static void progress_end() {
    if (tty_progress) {
        std::fprintf(stderr, "\r\x1b[2K\x1b[?25h\n");
        tty_progress = false;
    }
}
static void progress_print(const char* line) {
    if (!tty_progress) { std::fprintf(stderr, "%s\n", line); return; }
    const int cols = term_cols();
    std::fprintf(stderr, "\r\x1b[2K");
    if (cols > 0) {
        const int len = (int)std::strlen(line);
        const int keep = std::max(0, std::min(len, cols - 1));
        std::fwrite(line, 1, keep, stderr);
    } else {
        std::fputs(line, stderr);
    }
    std::fflush(stderr);
}

// ---- /proc/diskstats para provar I/O real ----
struct DiskStats { uint64_t writes_completed{0}; uint64_t sectors_written{0}; };
static bool read_diskstats_for_base(const std::string& base, DiskStats& out) {
    FILE* f = std::fopen("/proc/diskstats", "r");
    if (!f) return false;
    char line[1024];
    bool ok = false;
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long long major=0, minor=0; char name[64]={0};
        if (std::sscanf(line, "%llu %llu %63s", &major, &minor, name) != 3) continue;
        if (base != name) continue;
        std::vector<unsigned long long> v;
        char* p = std::strstr(line, name);
        if (!p) continue;
        p += std::strlen(name);
        char* end = p;
        while (*end) {
            while (*end && std::isspace((unsigned char)*end)) ++end;
            if (!*end) break;
            char* q = end; errno = 0;
            unsigned long long x = std::strtoull(q, &end, 10);
            if (q==end || errno) { while (*end && !std::isspace((unsigned char)*end)) ++end; continue; }
            v.push_back(x);
        }
        if (v.size() >= 7) {
            out.writes_completed = v[4];
            out.sectors_written  = v[6];
            ok = true; break;
        }
    }
    std::fclose(f);
    return ok;
}

// ===== Fwd
static bool run_pass_mt(int pass_idx, int pass_cnt, int fd, const std::string& dev,
                        uint64_t size, size_t block_bytes, int threads,
                        bool random_data, int pattern, SyncMode mode, int lsec,
                        size_t flush_interval_mb);

// ===== Worker (sem flush; flush é centralizado) =====
static void pass_worker(int tid, int fd, uint64_t size, size_t block_bytes,
                        int threads, bool random_data, int pattern,
                        SyncMode /*mode*/, int lsec, Progress* prog,
                        size_t /*flush_interval_mb*/)
{
    const uint64_t stride = (uint64_t)block_bytes * (uint64_t)threads;
    const size_t   align  = (size_t)std::max(lsec, 4096);

    AlignedBuf abuf; if(!abuf.alloc(block_bytes, align)) throw std::bad_alloc();
    unsigned char* buf = abuf.data();

    prog->active.fetch_add(1, std::memory_order_relaxed);

    for (uint64_t off = (uint64_t)tid * (uint64_t)block_bytes;
         off < size && !stop_flag.load(std::memory_order_relaxed);
         off += stride)
    {
        const size_t n = (size_t)std::min<uint64_t>(block_bytes, size - off);
        if (random_data)         fill_random(buf, n);
        else if (pattern >= 0)   fill_byte(buf, n, (unsigned char)pattern);
        else                     std::memset(buf, 0, n);

        ssize_t r = pwrite_all(fd, buf, n, off);
        if (r < 0) { break; }
        prog->bytes.fetch_add((uint64_t)r, std::memory_order_relaxed);
    }

    prog->active.fetch_sub(1, std::memory_order_relaxed);
}

// ===== Flush com spinner & diskstats =====
static bool flush_with_spinner(int fd, const std::string& dev_base) {
    DiskStats s0{};
    const bool have_stats = read_diskstats_for_base(dev_base, s0);
    std::atomic<bool> done{false}; int err=0;
    std::thread t([&](){ if(::fdatasync(fd)!=0) err=errno; done.store(true); });
    while(!done.load()){
        char sp=spinner_next(); double wr_mb=0.0; uint64_t ios=0;
        if (have_stats) {
            DiskStats s{}; if(read_diskstats_for_base(dev_base,s)){
                ios = (s.writes_completed>=s0.writes_completed)? (s.writes_completed-s0.writes_completed) : 0;
                uint64_t sec = (s.sectors_written>=s0.sectors_written)? (s.sectors_written-s0.sectors_written) : 0;
                wr_mb = (double)(sec*512ULL)/(1024.0*1024.0);
            }
        }
        char pl[256];
        std::snprintf(pl,sizeof(pl), "%s[sync]%s flushing… %c  ios=%" PRIu64 "  wr=%.1f MiB",
                      Colors::Blue, Colors::Reset, sp, (uint64_t)ios, wr_mb);
        progress_print(pl);
        std::this_thread::sleep_for(120ms);
    }
    t.join();
    if (err) { note("sync", Colors::Yellow, "fdatasync error: %s", std::strerror(err)); return false; }
    return true;
}

// ===== Pass runner =====
static double ema_speed(double prev, double sample, double alpha=0.30){ return alpha*sample + (1.0-alpha)*prev; }

static bool run_pass_mt(int pass_idx, int pass_cnt, int fd, const std::string& dev,
                        uint64_t size, size_t block_bytes, int threads,
                        bool random_data, int pattern, SyncMode mode, int lsec,
                        size_t flush_interval_mb)
{
    note("prog", Colors::Cyan, "pass %d/%d", pass_idx+1, pass_cnt);

    Progress prog;
    auto t0 = std::chrono::high_resolution_clock::now();
    double   last_ts = sec_since(t0);
    uint64_t last_bytes = 0;
    uint64_t last_flush_bytes = 0;
    double   inst_ema = 0.0;

    std::vector<std::thread> ths;
    ths.reserve(threads);
    for (int i=0;i<threads;i++) {
        ths.emplace_back(pass_worker, i, fd, size, block_bytes, threads,
                         random_data, pattern, mode, lsec, &prog, flush_interval_mb);
    }

    progress_begin();
    const double WARMUP_S = 0.5;

    while (prog.bytes.load(std::memory_order_relaxed) < size ||
           prog.active.load(std::memory_order_relaxed) > 0)
    {
        const double now = sec_since(t0);
        const double dt  = now - last_ts;

        if (dt >= 0.35) {
            const uint64_t done  = prog.bytes.load(std::memory_order_relaxed);
            const bool can_speed = (now >= WARMUP_S && done > 0);

            double inst = 0.0, avg = 0.0;
            if (can_speed) {
                inst = (double)(done - last_bytes) / 1048576.0 / (dt > 0 ? dt : 1);
                inst_ema = (inst_ema == 0.0 ? inst : ema_speed(inst_ema, inst));
                avg  =  (double)done / 1048576.0 / now;
            } else {
                inst_ema = 0.0;
            }

            std::string eta = "--:--:--";
            if (can_speed && avg > 0.0) {
                const double remain = (double)(size - done) / 1048576.0 / avg;
                eta = format_eta(remain);
            }

            char pline[256];
            char sp = spinner_next();
            std::snprintf(pline, sizeof(pline),
                "%s[prog]%s %d/%d %c %5.1f%%  %6.1f MB/s (avg %6.1f)  elapsed %s  ETA %s",
                Colors::Cyan, Colors::Reset,
                pass_idx+1, pass_cnt, sp,
                100.0*(double)done/(double)size,
                inst_ema, avg,
                format_eta(now).c_str(),
                eta.c_str()
            );
            progress_print(pline);

            if (flush_interval_mb >= 1) {
                const uint64_t flush_every = (uint64_t)flush_interval_mb << 20;
                if (done - last_flush_bytes >= flush_every) {
                    const std::string base = basename_of(dev);
                    (void)flush_with_spinner(fd, base);
                    last_flush_bytes = done;
                }
            }

            last_ts = now; last_bytes = done;
        }
        std::this_thread::sleep_for(80ms);
    }
    for (auto& t: ths) if (t.joinable()) t.join();

    {
        const std::string base = basename_of(dev);
        (void)flush_with_spinner(fd, base);
    }

    progress_end();

    double total_s = sec_since(t0);
    double pass_avg = ((double)size / 1048576.0) / (total_s > 0 ? total_s : 1.0);
    std::fprintf(stderr,
        "%s[prog]%s pass %d/%d finished — elapsed %s, avg %7.2f MB/s\n",
        Colors::Green, Colors::Reset,
        pass_idx+1, pass_cnt, format_eta(total_s).c_str(), pass_avg
    );

    return !stop_flag.load(std::memory_order_relaxed);
}

// ===== DoD =====
struct DoDPlan { std::vector<int> seq; }; // 0x100 => random, 0x00..0xFF => byte
static inline DoDPlan make_dod3() { return DoDPlan{ std::vector<int>{ 0x00, 0xFF, 0x100 } }; }
static inline DoDPlan make_dod7() { return DoDPlan{ std::vector<int>{ 0xF6, 0x00, 0xFF, 0x100, 0x00, 0xFF, 0x100 } }; }

// ===== Certificado =====
struct SampleEntry { uint64_t off; uint32_t len; std::string blake2b256; };
static void blake2b_256(const unsigned char* data, size_t n, unsigned char out[32]) {
    crypto_generichash(out, 32, data, (unsigned long long)n, nullptr, 0);
}
static bool write_certificate(const char* path, const char* dev, uint64_t size, int passes,
                              const std::vector<SampleEntry>& samples)
{
    FILE* f = std::fopen(path, "w");
    if(!f){ note("cert", Colors::Yellow, "open '%s' failed: %s", path, std::strerror(errno)); return false; }
    std::fprintf(f, "{\n");
    std::fprintf(f, "  \"device\": \"%s\",\n", dev);
    std::fprintf(f, "  \"size\": %" PRIu64 ",\n", (uint64_t)size); // <<< cast para evitar warning
    std::fprintf(f, "  \"method\": \"software_write\",\n");
    std::fprintf(f, "  \"passes\": %d,\n", passes);
    std::fprintf(f, "  \"samples\": [\n");
    for(size_t i=0;i<samples.size();i++){
        const auto& s = samples[i];
        std::fprintf(f,
          "    {\"offset\": %" PRIu64 ", \"len\": %u, \"blake2b256\": \"%s\"}%s\n",
          (uint64_t)s.off, (unsigned)s.len, s.blake2b256.c_str(),
          (i+1<samples.size()? ",":""));
    }
    std::fprintf(f, "  ]\n}\n");
    std::fclose(f);
    note("cert", Colors::Green, "wrote %s", path);
    return true;
}

// ===== Opções =====
struct Options {
    std::string target;
    int passes = 1;
    bool quick = true;
    bool verify_full = false;
    int verify_pct = 0;
    std::string cert_path;
    bool unmount = false;
    bool yes = false;             // --yes / --force
    int threads = 0;
    size_t flush_interval_mb = 0; // 0 = sem flush periódico
    bool block_user_set = false;
    int  block_mib = 4;
    SyncMode mode = SyncMode::None;

    // nativos
    bool nvme_sanitize = false;
    bool nvme_format = false;
    bool nvme_write_zeroes = false;
    bool scsi_sanitize = false;
    bool blk_discard = false;

    // utilitários
    bool list_only = false;
    bool test_all = false;

    // DoD
    bool dod3=false, dod7=false;
};

static void usage(const char* argv0){
    std::fprintf(stderr,
R"(Usage: %s [--list] [--test-all] --target /dev/sdX [options]

Options:
  --passes N              number of passes (default 1)
  --quick                 write zeros (default)
  --verify P              verify P%% by sampling (default 0). Use --verify-full for 100%%
  --verify-full           verify entire device (slow)
  --certificate FILE      write a JSON certificate with sampled hashes
  --threads N             number of threads (USB: default 1 if not specified)
  --block-mib N           block size in MiB (default 4; USB auto)
  --flush-interval MiB    periodic flush every N MiB (default 0 = disabled)
  --unmount               unmount partitions of the target before writing
  --yes | --force         do not ask for confirmation

  --nvme-sanitize         issue NVMe Sanitize (if supported)
  --nvme-format           issue NVMe Format NVM (if supported)
  --nvme-write-zeroes     offload zeroing via NVMe/BLKZEROOUT (if supported)
  --scsi-sanitize         issue SCSI SANITIZE(16) overwrite (if supported)
  --discard               offload TRIM/Discard via BLKDISCARD (if supported)

  --list                  list block devices and exit
  --test-all              run internal self-tests (safe, uses temp file) and exit
  --dod3                  DoD 5220.22-M (3-pass): 0x00, 0xFF, random
  --dod7                  DoD 5220.22-M ECE (7-pass): 0xF6, 0x00, 0xFF, random, 0x00, 0xFF, random
)", argv0);
}

static bool is_usb_device(const std::string& dev){
    std::string base = basename_of(dev);
    std::filesystem::path sys = std::filesystem::path("/sys/class/block")/base;
    std::error_code ec;
    auto phys = std::filesystem::canonical(sys, ec);
    if(ec) return false;
    return phys.string().find("/usb") != std::string::npos;
}
static bool is_nvme_node(const std::string& dev) {
    auto base = basename_of(dev);
    return base.rfind("nvme", 0) == 0;
}

static bool parse_args(int argc, char** argv, Options& O) {
    for (int i=1;i<argc;i++) {
        std::string a = argv[i];
        auto need = [&](int){ if(i+1>=argc){ usage(argv[0]); return false; } return true; };
        if (a=="--target")        { if(!need(1)) return false; O.target=argv[++i]; }
        else if (a=="--passes")   { if(!need(1)) return false; O.passes=std::max(1, std::atoi(argv[++i])); }
        else if (a=="--quick")    { O.quick=true; }
        else if (a=="--verify")   { if(!need(1)) return false; O.verify_pct=std::clamp(std::atoi(argv[++i]),0,100); }
        else if (a=="--verify-full"){ O.verify_full=true; }
        else if (a=="--certificate"){ if(!need(1)) return false; O.cert_path=argv[++i]; }
        else if (a=="--unmount")  { O.unmount=true; }
        else if (a=="--yes" || a=="--force") { O.yes=true; }
        else if (a=="--threads")  { if(!need(1)) return false; O.threads=std::max(1, std::atoi(argv[++i])); }
        else if (a=="--block-mib"){ if(!need(1)) return false; O.block_mib=std::max(1, std::atoi(argv[++i])); O.block_user_set=true; }
        else if (a=="--flush-interval"){ if(!need(1)) return false; O.flush_interval_mb=(size_t)std::max(0, std::atoi(argv[++i])); }
        // nativos
        else if (a=="--nvme-sanitize")     { O.nvme_sanitize = true; }
        else if (a=="--nvme-format")       { O.nvme_format = true; }
        else if (a=="--nvme-write-zeroes") { O.nvme_write_zeroes = true; }
        else if (a=="--scsi-sanitize")     { O.scsi_sanitize = true; }
        else if (a=="--discard")           { O.blk_discard = true; }
        // utilitários
        else if (a=="--list")              { O.list_only = true; }
        else if (a=="--test-all")          { O.test_all = true; }
        // DoD
        else if (a=="--dod3")              { O.dod3 = true; }
        else if (a=="--dod7")              { O.dod7 = true; }
        else { usage(argv[0]); note("err", Colors::Red, "unknown arg: %s", a.c_str()); return false; }
    }
    if (O.dod3 && O.dod7) {
        note("err", Colors::Red, "use apenas um: --dod3 OU --dod7");
        return false;
    }
    return true;
}

static bool validate_parameters(const Options& O) {
    if (O.block_mib <= 0 || O.block_mib > 1024) {
        note("config", Colors::Red, "Tamanho de bloco inválido: %d MiB", O.block_mib);
        return false;
    }
    if (O.threads < 0 || O.threads > 256) {
        note("config", Colors::Red, "Número de threads inválido: %d", O.threads);
        return false;
    }
    return true;
}

// helper: confere se /dev/src é o próprio device base (ex: sdd)
// ou uma partição do base (sdd1, nvme0n1p2, mmcblk0p1)
static bool is_this_dev_or_partition(const std::string& src, const std::string& base) {
    // precisa começar com "/dev/"
    constexpr const char* DEV = "/dev/";
    if (src.rfind(DEV, 0) != 0) return false;
    const std::string tail = src.substr(std::char_traits<char>::length(DEV)); // depois de "/dev/"

    if (tail == base) return true; // caso raro: dispositivo raiz montado

    // tem que começar com o base
    if (tail.rfind(base, 0) != 0) return false;

    // resto após o nome base
    const char* s = tail.c_str() + base.size();
    if (*s == '\0') return true; // igual ao base

    // partições podem ser: base + DIGITO(S)  (ex: sdd1)
    // ou base + 'p' + DIGITO(S) (ex: nvme0n1p1, mmcblk0p2)
    if (*s == 'p') ++s;

    if (!std::isdigit((unsigned char)*s)) return false;
    while (std::isdigit((unsigned char)*s)) ++s;

    return *s == '\0';
}

// desmonta todas as entradas de /proc/self/mounts que pertencem ao device
static bool unmount_partitions(const std::string& dev) {
    const std::string base = basename_of(dev);

    FILE* f = std::fopen("/proc/self/mounts", "r");
    if (!f) {
        note("unmount", Colors::Yellow, "não consegui abrir /proc/self/mounts: %s", std::strerror(errno));
        return false;
    }

    std::vector<std::pair<std::string,std::string>> hits; // (src, mountpoint)
    char src[512], mnt[512], rest[1024];

    while (std::fscanf(f, "%511s %511s %1023[^\n]\n", src, mnt, rest) == 3) {
        std::string ssrc = src;
        if (is_this_dev_or_partition(ssrc, base)) {
            hits.emplace_back(ssrc, std::string(mnt));
        }
    }
    std::fclose(f);

    if (hits.empty()) {
        note("unmount", Colors::Blue, "nenhuma partição montada de %s encontrada", dev.c_str());
        return true;
    }

    // desmontar do caminho mais profundo para o mais raso
    std::sort(hits.begin(), hits.end(),
              [](auto& a, auto& b){ return a.second.size() > b.second.size(); });

    bool all_ok = true;
    for (auto& [srcp, mntp] : hits) {
        if (umount2(mntp.c_str(), MNT_DETACH) != 0) {
            note("unmount", Colors::Yellow, "falha ao desmontar %s (%s): %s",
                 srcp.c_str(), mntp.c_str(), std::strerror(errno));
            all_ok = false;
        } else {
            note("unmount", Colors::Green, "desmontado: %s (%s)", srcp.c_str(), mntp.c_str());
        }
    }
    return all_ok;
}


static bool get_device_size(int fd, uint64_t& size, int& lsec){
    size = 0; lsec = 512;
#ifdef BLKGETSIZE64
    if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
        note("ioctl", Colors::Red, "BLKGETSIZE64 failed: %s", std::strerror(errno));
        return false;
    }
#else
#error "BLKGETSIZE64 not available on this platform"
#endif
#ifdef BLKSSZGET
    if (ioctl(fd, BLKSSZGET, &lsec) != 0) {
        note("ioctl", Colors::Yellow, "BLKSSZGET failed, defaulting to 512");
        lsec = 512;
    }
#endif
    return true;
}

// ===== List devices =====
static int list_devices_cli(){
    std::fprintf(stderr, "%s[list]%s scanning /sys/class/block ...\n", Colors::Cyan, Colors::Reset);
    std::printf("%-10s %-6s %-4s %-12s %-5s %-5s %-3s %-3s %s\n",
                "NAME","TYPE","BUS","SIZE","LSEC","PSEC","ROT","RM","MODEL");
    for (auto& e : std::filesystem::directory_iterator("/sys/class/block")) {
        auto base = e.path().filename().string();
        if (base.rfind("loop",0)==0 || base.rfind("ram",0)==0 || base.rfind("dm-",0)==0) continue;
        if (std::filesystem::exists(e.path()/"partition")) continue;

        std::error_code ec;
        auto phys = std::filesystem::canonical(e.path(), ec);
        bool usb = (!ec && phys.string().find("/usb") != std::string::npos);
        bool nvme = (base.rfind("nvme",0)==0);

        uint64_t sectors=0, lsec=512, psec=512;
        (void)read_file_u64((e.path()/"size").string(), sectors);
        (void)read_file_u64((e.path()/"queue"/"logical_block_size").string(), lsec);
        (void)read_file_u64((e.path()/"queue"/"physical_block_size").string(), psec);
        uint64_t size = sectors * 512ull;

        uint64_t rot=0, rm=0;
        (void)read_file_u64((e.path()/"queue"/"rotational").string(), rot);
        (void)read_file_u64((e.path()/"removable").string(), rm);

        std::string model = read_file_str((e.path()/"device"/"model").string());
        if (model.empty()) model = read_file_str((e.path()/"device"/"name").string());

        const char* bus = nvme? "NVMe" : (usb? "USB":"SATA");
        const char* type = nvme? "SSD" : (rot? "HDD":"SSD");

        char szbuf[32];
        double gib = (double)size / (1024.0*1024.0*1024.0);
        if (gib < 1.0) {
            double mib = (double)size / (1024.0*1024.0);
            std::snprintf(szbuf,sizeof(szbuf),"%.1fMiB", mib);
        } else {
            std::snprintf(szbuf,sizeof(szbuf),"%.2fGiB", gib);
        }

        std::printf("%-10s %-6s %-4s %-12s %-5" PRIu64 " %-5" PRIu64 " %-3" PRIu64 " %-3" PRIu64 " %s\n",
                    base.c_str(), type, bus, szbuf, (uint64_t)lsec, (uint64_t)psec, (uint64_t)rot, (uint64_t)rm, model.c_str());
    }
    return 0;
}

// ===== Caminhos nativos =====
static bool try_blkdiscard(int fd, uint64_t size) {
#ifdef BLKDISCARD
    note("discard", Colors::Cyan, "attempting BLKDISCARD over %" PRIu64 " bytes", (uint64_t)size);
    const uint64_t chunk = (uint64_t)1 << 30;
    uint64_t off = 0;
    while (off < size) {
        uint64_t len = std::min<uint64_t>(chunk, size - off);
        uint64_t range[2] = { off, len };
        if (ioctl(fd, BLKDISCARD, &range) != 0) {
            note("discard", Colors::Yellow, "BLKDISCARD failed at off=%" PRIu64 " len=%" PRIu64 ": %s",
                 (uint64_t)off, (uint64_t)len, std::strerror(errno));
            return false;
        }
        off += len;
    }
    note("discard", Colors::Green, "BLKDISCARD completed");
    return true;
#else
    note("discard", Colors::Yellow, "BLKDISCARD not available");
    return false;
#endif
}
static bool try_blkzeroout(int fd, uint64_t size) {
#ifdef BLKZEROOUT
    note("nvme/wzero", Colors::Cyan, "attempting BLKZEROOUT over %" PRIu64 " bytes", (uint64_t)size);
    uint64_t range[2] = { 0, size };
    if (ioctl(fd, BLKZEROOUT, &range) != 0) {
        note("nvme/wzero", Colors::Yellow, "BLKZEROOUT failed: %s", std::strerror(errno));
        return false;
    }
    note("nvme/wzero", Colors::Green, "BLKZEROOUT completed");
    return true;
#else
    note("nvme/wzero", Colors::Yellow, "BLKZEROOUT not available");
    return false;
#endif
}

#if defined(USE_LIBNVME)
#ifndef NVME_ADMIN_FORMAT_NVM
#define NVME_ADMIN_FORMAT_NVM  0x80
#endif
#ifndef NVME_ADMIN_SANITIZE
#define NVME_ADMIN_SANITIZE    0x84
#endif
static bool nvme_admin_simple(int fd, __u8 opcode, __u32 nsid, __u64 cdw10_15[6]) {
    struct nvme_admin_cmd cmd{};
    cmd.opcode = opcode;
    cmd.nsid = nsid;
    if (cdw10_15) {
        __u32* p = reinterpret_cast<__u32*>(cdw10_15);
        cmd.cdw10 = p[0];
        cmd.cdw11 = p[1];
        cmd.cdw12 = p[2];
        cmd.cdw13 = p[3];
        cmd.cdw14 = p[4];
        cmd.cdw15 = p[5];
    }
    int rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (rc < 0) {
        note("nvme", Colors::Yellow, "NVME_IOCTL_ADMIN_CMD (opcode=0x%02x) failed: %s", opcode, std::strerror(errno));
        return false;
    }
    return true;
}
#endif // USE_LIBNVME

static bool try_nvme_write_zeroes(int fd, uint64_t size) {
#if defined(USE_LIBNVME)
    if (try_blkzeroout(fd, size)) return true;
    note("nvme/wzero", Colors::Yellow, "falling back to software write");
    return false;
#else
    return try_blkzeroout(fd, size);
#endif
}
static bool try_nvme_format(int fd) {
#if defined(USE_LIBNVME)
    __u64 cdw[6] = {};
    if (!nvme_admin_simple(fd, NVME_ADMIN_FORMAT_NVM, 0 /*nsid*/, cdw)) return false;
    note("nvme/format", Colors::Green, "NVMe Format NVM issued");
    return true;
#else
    note("nvme/format", Colors::Yellow, "not compiled with USE_LIBNVME");
    return false;
#endif
}
static bool try_nvme_sanitize(int fd) {
#if defined(USE_LIBNVME)
    __u64 cdw[6] = {};
    const __u32 cdw10 = 0x1; // SANACT=1 (block erase)
    reinterpret_cast<__u32*>(cdw)[0] = cdw10;
    if (!nvme_admin_simple(fd, NVME_ADMIN_SANITIZE, 0 /*nsid*/, cdw)) return false;
    note("nvme/sanitize", Colors::Green, "NVMe Sanitize issued (SANACT=1)");
    return true;
#else
    note("nvme/sanitize", Colors::Yellow, "not compiled with USE_LIBNVME");
    return false;
#endif
}
static bool try_scsi_sanitize_overwrite(int fd) {
#if defined(USE_SG_IO)
    unsigned char cdb[16] = {};
    cdb[0] = 0x48;   // SANITIZE(16)
    cdb[1] = 0x01;   // SERVICE ACTION: OVERWRITE

    unsigned char sense[32] = {};
    sg_io_hdr_t io{};
    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_NONE;
    io.cmdp = cdb;
    io.cmd_len = sizeof(cdb);
    io.mx_sb_len = sizeof(sense);
    io.sbp = sense;
    io.timeout = 600000; // 10 min

    int rc = ioctl(fd, SG_IO, &io);
    if (rc < 0) { note("scsi/sanitize", Colors::Yellow, "SG_IO failed: %s", std::strerror(errno)); return false; }
    if ((io.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        note("scsi/sanitize", Colors::Yellow, "device CHECK CONDITION (status=0x%x, sense=%02x %02x)",
             io.status, sense[0], sense[2]);
        return false;
    }
    note("scsi/sanitize", Colors::Green, "SCSI SANITIZE(Overwrite) issued");
    return true;
#else
    note("scsi/sanitize", Colors::Yellow, "not compiled with USE_SG_IO");
    return false;
#endif
}

// ===== Orquestração =====
static bool do_wipe_mt(int fd, const std::string& dev, uint64_t size, size_t block_bytes,
                       int passes, bool final_zero, SyncMode mode, int lsec,
                       int threads, size_t flush_interval_mb,
                       std::vector<SampleEntry>* out_samples)
{
    note("wipe", Colors::Cyan, "dev=%s size=%" PRIu64 " block=%zu threads=%d passes=%d final_zero=%d",
         dev.c_str(), (uint64_t)size, block_bytes, threads, passes, (int)final_zero);

    for (int pass=0; pass<passes && !stop_flag.load(); ++pass) {
        bool last = (pass == passes-1);
        bool write_zero = (final_zero && last);
        bool random_data = !write_zero;
        int  pattern = write_zero ? 0x00 : -1;

        if (!run_pass_mt(pass, passes, fd, dev, size, block_bytes, threads,
                         random_data, pattern, mode, lsec, flush_interval_mb))
            return false;
    }

    note("wipe", Colors::Green, "done");

    if (out_samples) {
        SecureBuf tmp(4096);
        for (int i=0;i<64;i++){
            uint64_t off = (randombytes_random() % (size?size:1));
            off = (off/4096)*4096;
            if ((off+4096) > size) off = (size>4096? size-4096:0);
            if (pread_all(fd, tmp.data(), 4096, off) < 0) continue;
            unsigned char h[32]; blake2b_256(tmp.data(), 4096, h);
            out_samples->push_back(SampleEntry{off, 4096, hex(h, 32)});
        }
    }
    return true;
}

static bool run_dod_mt(int fd, const std::string& dev, uint64_t size, size_t block_bytes,
                       const DoDPlan& dp, SyncMode mode, int lsec, int threads,
                       size_t flush_interval_mb, std::vector<SampleEntry>* out_samples)
{
    note("dod", Colors::Magenta, "applying DoD sequence (%zu passes)", dp.seq.size());
    for (size_t i=0;i<dp.seq.size() && !stop_flag.load(); ++i) {
        int pat = dp.seq[i];
        bool random_data = (pat == 0x100);
        int  pattern = random_data ? -1 : pat;
        if (!run_pass_mt((int)i, (int)dp.seq.size(), fd, dev, size, block_bytes, threads,
                         random_data, pattern, mode, lsec, flush_interval_mb))
            return false;
    }

    if (out_samples){
        SecureBuf tmp(4096);
        for (int i=0;i<64;i++){
            uint64_t off = (randombytes_random() % (size?size:1));
            off = (off/4096)*4096;
            if ((off+4096)>size) off = (size>4096? size-4096:0);
            if (pread_all(fd, tmp.data(), 4096, off)<0) continue;
            unsigned char h[32]; blake2b_256(tmp.data(), 4096, h);
            out_samples->push_back(SampleEntry{off, 4096, hex(h,32)});
        }
    }
    return true;
}

// ===== Self-test =====
static int run_self_test_all(){
    note("selftest", Colors::Cyan, "creating temp file…");
    char tmpl[] = "/tmp/defrogwipe_test.XXXXXX";
    int fd_raw = ::mkstemp(tmpl);
    if (fd_raw < 0) { note("selftest", Colors::Red, "mkstemp failed: %s", std::strerror(errno)); return 2; }
    ScopedFD fd(fd_raw);
    ::unlink(tmpl);

    const uint64_t size = 32ull<<20; // 32 MiB
    if (ftruncate(fd, (off_t)size) != 0) {
        note("selftest", Colors::Red, "ftruncate failed: %s", std::strerror(errno));
        return 2;
    }
    int lsec = 512;
    size_t block_bytes = 1ull<<20; // 1 MiB
    int threads = 2;
    size_t flush_interval_mb = 0;

    note("selftest", Colors::Magenta, "pass 1/2: random write…");
    if (!run_pass_mt(0,2,fd.get(),"selftest",size,block_bytes,threads,true,-1,SyncMode::None,lsec,flush_interval_mb)){
        note("selftest", Colors::Red, "random pass failed");
        return 2;
    }
    note("selftest", Colors::Magenta, "pass 2/2: zero write…");
    if (!run_pass_mt(1,2,fd.get(),"selftest",size,block_bytes,threads,false,0x00,SyncMode::None,lsec,flush_interval_mb)){
        note("selftest", Colors::Red, "zero pass failed");
        return 2;
    }
    note("selftest", Colors::Green, "OK");
    return 0;
}

// ===== main =====
int main(int argc, char** argv) {
    std::signal(SIGINT,  on_termination);
    std::signal(SIGTERM, on_termination);
    std::signal(SIGHUP,  on_termination);

    if (sodium_init() < 0) { note("init", Colors::Red, "libsodium init failed"); return 2; }

    Options O;
    if (!parse_args(argc, argv, O)) return 2;
    if (!validate_parameters(O))    return 2;

    setvbuf(stderr, nullptr, _IONBF, 0);

    if (O.list_only) { int rc = list_devices_cli(); std::fflush(nullptr); return rc==0?0:2; }
    if (O.test_all)  { int rc = run_self_test_all(); std::fflush(nullptr); return rc; }

    if (O.target.empty()) { usage(argv[0]); note("err", Colors::Red, "--target required"); return 2; }

    // validação do alvo
    if (!std::filesystem::exists(O.target)) {
        note("open", Colors::Red, "target '%s' não existe", O.target.c_str());
        return 2;
    }
    struct stat st{}; if (stat(O.target.c_str(), &st)!=0 || !S_ISBLK(st.st_mode)) {
        note("open", Colors::Red, "target '%s' não é bloco (S_ISBLK)", O.target.c_str());
        return 2;
    }
    if (geteuid()!=0) {
        note("warn", Colors::Yellow, "não está como root — operações podem falhar");
    }

    const bool usb = is_usb_device(O.target);
    if (usb) {
        if (O.threads == 0) {
            O.threads = 1;
            note("tune", Colors::Yellow, "USB detected → forcing single-thread mode for stability");
        }
        if (!O.block_user_set) {
            O.block_mib = 4;
            note("tune", Colors::Yellow, "USB detected → block-size=4 MiB");
        }
    }

    if (!O.yes) {
        note("ask", Colors::Blue, "About to WIPE %s — THIS DESTROYS DATA. Use --yes/--force para confirmar.", O.target.c_str());
        return 1;
    }

    if (O.unmount) unmount_partitions(O.target);

    ScopedFD fd_dev(O.target, O_RDWR | O_LARGEFILE);
    if (!fd_dev.is_open()) {
        note("open", Colors::Red, "open %s: %s", O.target.c_str(), std::strerror(errno));
        return 2;
    }
    if (!check_device_writable(fd_dev.get())) return 2;

    uint64_t size = 0; int lsec=512;
    if (!get_device_size(fd_dev.get(), size, lsec)) return 2;
    note("info", Colors::Cyan, "device=%s size=%" PRIu64 " bytes lsec=%d", O.target.c_str(), (uint64_t)size, lsec);

    int threads = (O.threads>0 ? O.threads : (usb ? 1 : (int)std::max(1u, std::thread::hardware_concurrency())));
    size_t block_bytes = (size_t)O.block_mib * (1<<20);
    // ajustar para múltiplo do setor lógico
    block_bytes = ((block_bytes + (size_t)lsec - 1) / (size_t)lsec) * (size_t)lsec;

    // DoD?
    if (O.dod3 || O.dod7) {
        DoDPlan dp = O.dod3 ? make_dod3() : make_dod7();
        std::vector<SampleEntry> samples;
        bool ok = run_dod_mt(fd_dev.get(), O.target, size, block_bytes, dp, O.mode, lsec, threads,
                             O.flush_interval_mb, &samples);

        if (ok && !O.cert_path.empty()) {
            if (samples.empty()) {
                SecureBuf tmp(4096);
                for (int i=0;i<64;i++){
                    uint64_t off = (randombytes_random() % (size?size:1));
                    off = (off/4096)*4096;
                    if ((off+4096)>size) off = (size>4096? size-4096:0);
                    if (pread_all(fd_dev.get(), tmp.data(), 4096, off)<0) continue;
                    unsigned char h[32]; blake2b_256(tmp.data(), 4096, h);
                    samples.push_back(SampleEntry{off, 4096, hex(h,32)});
                }
            }
            (void)write_certificate(O.cert_path.c_str(), O.target.c_str(), size, O.passes, samples);
        }

        note("main", ok? Colors::Green : Colors::Red, ok? "all operations completed successfully" : "failed");
        std::fflush(nullptr);
        return ok?0:2;
    }

    // Caminhos nativos antes do software
    bool native_done = false;
    if (O.blk_discard) {
        if (try_blkdiscard(fd_dev.get(), size)) { native_done = true; note("native", Colors::Green, "discard completed"); }
        else note("native", Colors::Yellow, "discard failed — fallback to software");
    }
    if (!native_done && O.nvme_write_zeroes) {
        if (!is_nvme_node(O.target)) note("nvme/wzero", Colors::Yellow, "target is not NVMe — skipping");
        else if (try_nvme_write_zeroes(fd_dev.get(), size)) native_done = true;
        else note("nvme/wzero", Colors::Yellow, "write-zeroes failed — fallback");
    }
    if (!native_done && O.nvme_format) {
        if (!is_nvme_node(O.target)) note("nvme/format", Colors::Yellow, "target is not NVMe — skipping");
        else if (try_nvme_format(fd_dev.get())) native_done = true;
        else note("nvme/format", Colors::Yellow, "format failed — fallback");
    }
    if (!native_done && O.nvme_sanitize) {
        if (!is_nvme_node(O.target)) note("nvme/sanitize", Colors::Yellow, "target is not NVMe — skipping");
        else if (try_nvme_sanitize(fd_dev.get())) native_done = true;
        else note("nvme/sanitize", Colors::Yellow, "sanitize failed — fallback");
    }
    if (!native_done && O.scsi_sanitize) {
        if (try_scsi_sanitize_overwrite(fd_dev.get())) native_done = true;
        else note("scsi/sanitize", Colors::Yellow, "sanitize failed — fallback");
    }

    // Execução principal (software)
    bool ok=false;
    std::vector<SampleEntry> samples;

    if (native_done) {
        ok = true;
    } else if (O.passes == 1 && O.quick) {
        if (run_pass_mt(0, 1, fd_dev.get(), O.target, size, block_bytes, threads,
                        /*random=*/false, /*pattern=*/0x00, O.mode, lsec, O.flush_interval_mb))
            ok = true;
    } else {
        ok = do_wipe_mt(fd_dev.get(), O.target, size, block_bytes, O.passes,
                        /*final_zero=*/true, O.mode, lsec, threads,
                        O.flush_interval_mb, &samples);
    }

    // Verificação (pular para DoD, pois último passe não-zerado)
    if (ok && (O.verify_full || O.verify_pct>0) && !native_done) {
        if (O.dod3 || O.dod7) {
            note("verify", Colors::Yellow, "verificação ignorada para DoD (último passe não-zero)");
        } else {
            note("verify", Colors::Cyan, "verifying (%s)…", O.verify_full? "full" : "sample");
            SecureBuf tmp(4096);
            std::mt19937_64 rng{std::random_device{}()};
            auto check_block = [&](uint64_t off){
                if (pread_all(fd_dev.get(), tmp.data(), tmp.size(), off) < 0) return false;
                for(size_t i=0;i<tmp.size();i++){ if(tmp.data()[i]!=0){ return false; } }
                return true;
            };
            bool v_ok=true;
            if (O.verify_full) {
                const size_t step = 4096;
                for (uint64_t off=0; off<size && !stop_flag; off += step) {
                    if (!check_block(off)) { v_ok=false; break; }
                }
            } else {
                int samples_n = std::max(1, O.verify_pct);
                for (int i=0;i<samples_n && !stop_flag;i++){
                    uint64_t off = (rng()% (size?size:1));
                    off = (off/4096)*4096;
                    if ((off+4096)>size) off = (size>4096? size-4096:0);
                    if (!check_block(off)) { v_ok=false; break; }
                }
            }
            ok = ok && v_ok;
            note("verify", v_ok? Colors::Green : Colors::Red, v_ok? "ok" : "FAILED");
        }
    }

    if (ok && !O.cert_path.empty() && !native_done) {
        if (samples.empty()) {
            SecureBuf tmp(4096);
            for (int i=0;i<64;i++){
                uint64_t off = (randombytes_random() % (size?size:1));
                off = (off/4096)*4096;
                if ((off+4096)>size) off = (size>4096? size-4096:0);
                if (pread_all(fd_dev.get(), tmp.data(), 4096, off)<0) continue;
                unsigned char h[32]; blake2b_256(tmp.data(), 4096, h);
                samples.push_back(SampleEntry{off, 4096, hex(h,32)});
            }
        }
        (void)write_certificate(O.cert_path.c_str(), O.target.c_str(), size, O.passes, samples);
    }

    note("main", ok? Colors::Green : Colors::Red, ok? "all operations completed successfully" : "failed");
    std::fflush(nullptr);
    return ok?0:2;
}
