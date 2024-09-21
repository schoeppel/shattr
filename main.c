#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "sha256.h"


#define BUFSIZE (8192*1024)
uint8_t buf[BUFSIZE];

static uint64_t nsecs() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int sha256_file_contents(struct sha256_state *state, const char *path) {
	int fd = open(path, O_RDONLY);
	if (fd == -1) return 1;

	int ret;
	sha256_init(state);
	while ((ret = read(fd, buf, sizeof(buf))) != 0) {
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				close(fd);
				return 1;
			}
		}

		if (ret % 64 == 0) {
			sha256_process(state, buf, ret);
		} else {
			size_t full_blocks = ret - (ret % 64);
			sha256_process(state, buf, full_blocks);
			sha256_final(state, buf + full_blocks, ret % 64);
		}
	}
	sha256_final(state, NULL, 0);
	close(fd);
	return 0;
}

static int sha256_extattr(struct sha256_state *state, const char *path) {
	char buf[61];
	buf[60] = '\0';
	if (getxattr(path, "user.shattr", buf, sizeof(buf)-1) != sizeof(buf)-1) {
		return 1;
	}
	uint64_t nsecs;
	if (sscanf(buf+44,  "%016" PRIx64, &nsecs) != 1) {
		return 1;
	}

	struct stat sb;
	if (stat(path, &sb)) {
		perror(path);
		return 1;
	}

	uint64_t mtime_nsecs = sb.st_mtim.tv_sec * 1000000000ULL + sb.st_mtim.tv_nsec;
	if (mtime_nsecs != nsecs) {
		return 2; /* outdated */
	}

	return sha256_b64_read(state, buf);
}

static int sha256_bench() {
	memset(buf, 'a', sizeof(buf));

	uint64_t start = nsecs();
	struct sha256_state s;
	sha256_init(&s);

	const unsigned int loops = 1073741824/BUFSIZE;
	for (unsigned int i = 0; i < loops; i++) {
		sha256_process(&s, buf, sizeof(buf));
	}
	sha256_final(&s, NULL, 0);
	char hex[65];
	sha256_hex(&s, hex);
	if (strcmp(hex, "c4d3e5935f50de4f0ad36ae131a72fb84a53595f81f92678b42b91fc78992d84")) {
		printf("calculated digest is wrong\n");
		return 1;
	}

	uint64_t stop = nsecs();
	printf("%lu bytes in %lu nsecs: %lu MByte/s\n",
		(uint64_t)loops * sizeof(buf), stop - start,
		(loops * sizeof(buf)) / ((stop - start)/1000)
	);
	return 0;
}


static int print_digest(const char *path, int use_extattr) {
	struct sha256_state s;

	int r = 1;
	const char* info = "CALC    ";

	if (use_extattr) {
		r = sha256_extattr(&s, path);
		if (r == 0) {
			info = "CACHED  ";
		} else if (r == 2) {
			info = "OUTDATED";
		}
	}

	if (r != 0) {
		if (sha256_file_contents(&s, path)) {
			perror(path);
			return 1;
		}
	}

	char hex[65];
	sha256_hex(&s, hex);
	printf("%s  %s  %s\n", info, hex, path);
	return 0;

}

static int save_digest(const char *path, int force) {
	struct sha256_state s;

	if (sha256_extattr(&s, path) == 0 && force == 0) {
		return 0;
	}

	uint64_t start = nsecs();
	if (sha256_file_contents(&s, path)) {
		perror(path);
		return 1;
	}
	uint64_t stop = nsecs();

	struct stat sb;
	if (stat(path, &sb)) {
		perror(path);
		return 1;
	}

	uint64_t mtime_nsecs = sb.st_mtim.tv_sec * 1000000000ULL + sb.st_mtim.tv_nsec;
	char val[44+17];
	sha256_b64(&s, val);
	snprintf(val+44, 17, "%016" PRIx64, mtime_nsecs);

	printf("%4d MByte/s  %s\n", (unsigned int)(sb.st_size / ((stop - start)/1000)), path);

	if (setxattr(path, "user.shattr", val, 60, 0)) {
		perror(path);
		return 1;
	}

	return 0;
}

static int check_digest(const char *path) {
	struct sha256_state s, scalc;

	int r = sha256_extattr(&s, path);
	if (r == 2) {
		printf("OUTDATED  %s\n", path);
		return 2;
	} else if (r != 0) {
		printf("MISSING   %s\n", path);
		return 2;
	}

	if (sha256_file_contents(&scalc, path)) {
		perror(path);
		return 1;
	}

	if (memcmp(s.state, scalc.state, sizeof(s.state))) {
		printf("NOT OK  %s\n", path);
		return 1;
	}

	printf("OK        %s\n", path);
	return 0;
}

static int convert_attributes(const char *path) {
	char digest[128];
	char ts[128];

	memset(digest, 0, sizeof(digest));
	memset(ts, 0, sizeof(ts));

	if (getxattr(path, "user.shatag.sha256", digest, sizeof(digest)) <= 0) return 0;
	if (getxattr(path, "user.shatag.ts", ts, sizeof(ts)) <= 0) return 0;

	struct sha256_state s;
	if (sha256_hex_read(&s, digest[0] == '"' ? digest+1 : digest)) return 1;
	uint64_t time_s, time_ns;
	if (sscanf(ts[0] == '"' ? ts+1 : ts, "%" PRIu64 ".%" PRIu64, &time_s, &time_ns) != 2) return 1;

	uint64_t mtime_nsecs = time_s * 1000000000ULL + time_ns;
	char val[44+17];
	sha256_b64(&s, val);
	snprintf(val+44, 17, "%016" PRIx64, mtime_nsecs);

	if (setxattr(path, "user.shattr", val, 60, 0)) {
		perror(path);
		return 1;
	} else {
		printf("CONVERTED  %s\n", path);

		removexattr(path, "user.shatag.sha256");
		removexattr(path, "user.shatag.ts");
	}

	return 0;
}


int main(int argc, char** argv) {
	if (argc <= 1) {
		fprintf(stderr,
			"Usage: %s [OPTION]... [FILE]...\n"
			"Save SHA-256 digest of file contents in extended attribute."
			"\n"
			"Options:\n"
			"  -s      save digest in extended attribute\n"
			"  -S      save digest in extended attribute (force recalc)\n"
			"  -c      read digest from extended attribute and check file\n"
			"  -p      print SHA-256 digest\n"
			"  -P      print SHA-256 digest (don't use extended attribute)\n"
			"  -t      convert (c)shatag attributes\n"
			"  -b      run internal benchmark\n"
			"Default option is '-s'\n\n"
		, argv[0]);
		return 1;
	}


	unsigned int num_errs = 0;
	unsigned int num_outdated = 0;
	char mode = 's';
	char c;
	while ((c = getopt (argc, argv, "sScpPbt")) != -1) {
		switch (c) {
			case 's':
			case 'S':
			case 'c':
			case 'p':
			case 'P':
			case 't':
				mode = c;
				break;
			case 'b':
				return sha256_bench();
			case '?':
			default:
				return 1;
		}
	}

	int r;
	for (int i = optind; i < argc; i++) {
		switch (mode) {
			case 'P':
				num_errs += print_digest(argv[i], 0);
				break;
			case 'p':
				num_errs += print_digest(argv[i], 1);
				break;
			case 's':
				num_errs += save_digest(argv[i], 0);
				break;
			case 'S':
				num_errs += save_digest(argv[i], 1);
				break;
			case 'c':
				r = check_digest(argv[i]);
				if (r == 2) num_outdated++;
				if (r == 1) num_errs++;

				break;
			case 't':
				num_errs += convert_attributes(argv[i]);
		}
	}

	if (num_outdated) {
		printf("%u outdated/missing\n", num_outdated);
	}

	if (num_errs) {
		printf("%u Errors\n", num_errs);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;

}
