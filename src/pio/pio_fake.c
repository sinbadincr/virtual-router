#include "pio_fake.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FAKE_MAX_IFS 32
#define FAKE_QLEN 256

struct fake_frame {
    uint8_t data[MBUF_DATA_SIZE];
    size_t len;
    int vlan;
};

struct fake_if {
    int exists, opened;
    int adopted_fd1; /* fd passed to adopt(), plus one; closed with the handle */
    char name[16];
    uint8_t mac[6];
    int mtu;
    struct fake_frame rx[FAKE_QLEN];
    size_t rx_head, rx_n;
    struct fake_frame tx[FAKE_QLEN];
    size_t tx_n;
};

static struct fake_if ifs[FAKE_MAX_IFS];

void pio_fake_reset(void) {
    memset(ifs, 0, sizeof ifs);
}

void pio_fake_add_if(const char *ifname, const uint8_t mac[6], int mtu) {
    for (int i = 0; i < FAKE_MAX_IFS; i++) {
        if (!ifs[i].exists) {
            ifs[i].exists = 1;
            strncpy(ifs[i].name, ifname, sizeof ifs[i].name - 1);
            memcpy(ifs[i].mac, mac, 6);
            ifs[i].mtu = mtu;
            return;
        }
    }
}

static void *f_open(const char *ifname) {
    for (int i = 0; i < FAKE_MAX_IFS; i++)
        if (ifs[i].exists && strcmp(ifs[i].name, ifname) == 0) {
            ifs[i].opened = 1;
            return &ifs[i];
        }
    errno = ENODEV;
    return NULL;
}

static void f_close(void *h) {
    struct fake_if *f = h;
    f->opened = 0;
    if (f->adopted_fd1) {
        close(f->adopted_fd1 - 1);
        f->adopted_fd1 = 0;
    }
}

static void *f_adopt(int fd, const char *ifname) {
    struct fake_if *f = f_open(ifname);
    if (f)
        f->adopted_fd1 = fd + 1;
    return f;
}

static int f_rx(void *h, struct mbuf **m, int max) {
    struct fake_if *f = h;
    int n = 0;
    while (n < max && f->rx_n > 0) {
        struct mbuf *b = mbuf_alloc();
        if (!b)
            break;
        struct fake_frame *fr = &f->rx[f->rx_head];
        memcpy(mbuf_data(b), fr->data, fr->len);
        b->len = (uint16_t)fr->len;
        b->vlan_tagged = (uint8_t)fr->vlan;
        f->rx_head = (f->rx_head + 1) % FAKE_QLEN;
        f->rx_n--;
        m[n++] = b;
    }
    return n;
}

static int f_tx(void *h, struct mbuf **m, int n) {
    struct fake_if *f = h;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        if (f->tx_n < FAKE_QLEN) {
            memcpy(f->tx[f->tx_n].data, mbuf_data(m[i]), m[i]->len);
            f->tx[f->tx_n].len = m[i]->len;
            f->tx_n++;
            sent++;
        }
        mbuf_free(m[i]);
    }
    return sent;
}

static int f_fd(void *h) {
    (void)h;
    return -1;
}

static int f_mac(void *h, uint8_t mac[6]) {
    memcpy(mac, ((struct fake_if *)h)->mac, 6);
    return 0;
}

static int f_mtu(void *h) {
    return ((struct fake_if *)h)->mtu;
}

const struct pio_ops pio_fake_ops = {"fake", f_open, f_close, f_rx, f_tx, f_fd, f_mac, f_mtu, f_adopt};

static int inject(void *h, const void *frame, size_t len, int vlan) {
    struct fake_if *f = h;
    if (f->rx_n >= FAKE_QLEN || len > MBUF_DATA_SIZE - MBUF_HEADROOM)
        return -1;
    struct fake_frame *fr = &f->rx[(f->rx_head + f->rx_n) % FAKE_QLEN];
    memcpy(fr->data, frame, len);
    fr->len = len;
    fr->vlan = vlan;
    f->rx_n++;
    return 0;
}

int pio_fake_inject(void *h, const void *frame, size_t len) {
    return inject(h, frame, len, 0);
}

int pio_fake_inject_vlan(void *h, const void *frame, size_t len) {
    return inject(h, frame, len, 1);
}

size_t pio_fake_tx_count(void *h) {
    return ((struct fake_if *)h)->tx_n;
}

const uint8_t *pio_fake_tx_frame(void *h, size_t idx, size_t *len) {
    struct fake_if *f = h;
    if (idx >= f->tx_n)
        return NULL;
    *len = f->tx[idx].len;
    return f->tx[idx].data;
}

void pio_fake_clear_tx(void *h) {
    ((struct fake_if *)h)->tx_n = 0;
}
