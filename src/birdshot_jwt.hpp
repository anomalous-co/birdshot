#pragma once

// Minimal JWT verification for birdshot.
//
// Supports three modes (see birdshot_state.hpp::AuthMode):
//   DEV   - split + decode claims, NO signature check (localhost/dev only)
//   HS256 - HMAC-SHA256 against a shared secret
//   RS256 - RSA-SHA256 against a JWKS public key (modulus/exponent)
//
// The JSON claim extractor here is deliberately tiny: JWT header/payload are
// flat JSON objects, so we scan for top-level keys and read a string or number
// value. `aud` may be a string or an array; we handle "contains" for arrays.
// (Not a general JSON parser — fine for token claim sets; see design doc.)

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "birdshot_state.hpp"

namespace birdshot {

struct Claims {
	bool ok = false;
	std::string sub;
	std::string jti;
	std::string iss;
	std::string aud_raw; // raw value text (string contents, or array text)
	int64_t exp_us = 0;
	std::string error; // set when ok == false
};

// ---- base64url -------------------------------------------------------------

inline int B64Val(unsigned char c) {
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '-')
		return 62;
	if (c == '_')
		return 63;
	return -1;
}

inline bool B64UrlDecode(const std::string &in, std::string &out) {
	out.clear();
	int buf = 0, bits = 0;
	for (unsigned char c : in) {
		if (c == '=')
			break;
		int v = B64Val(c);
		if (v < 0)
			return false;
		buf = (buf << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back(static_cast<char>((buf >> bits) & 0xFF));
		}
	}
	return true;
}

inline std::string B64UrlEncode(const std::string &in) {
	static const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::string out;
	int buf = 0, bits = 0;
	for (unsigned char c : in) {
		buf = (buf << 8) | c;
		bits += 8;
		while (bits >= 6) {
			bits -= 6;
			out.push_back(tbl[(buf >> bits) & 0x3F]);
		}
	}
	if (bits > 0)
		out.push_back(tbl[(buf << (6 - bits)) & 0x3F]);
	return out;
}

// ---- tiny flat-JSON value reader ------------------------------------------

// Find top-level `"key"` and return its value text. For strings, returns the
// unescaped contents (basic \" \\ \/ handling). For numbers, the digits. For
// arrays/objects, the raw bracketed text. Returns false if absent.
inline bool JsonField(const std::string &json, const std::string &key, std::string &out, bool &was_string) {
	std::string needle = "\"" + key + "\"";
	size_t p = 0;
	while ((p = json.find(needle, p)) != std::string::npos) {
		// Ensure it is a key (followed by optional ws then ':').
		size_t c = p + needle.size();
		while (c < json.size() && (json[c] == ' ' || json[c] == '\t' || json[c] == '\n' || json[c] == '\r'))
			c++;
		if (c >= json.size() || json[c] != ':') {
			p += needle.size();
			continue;
		}
		c++;
		while (c < json.size() && (json[c] == ' ' || json[c] == '\t' || json[c] == '\n' || json[c] == '\r'))
			c++;
		if (c >= json.size())
			return false;
		if (json[c] == '"') {
			was_string = true;
			out.clear();
			c++;
			while (c < json.size() && json[c] != '"') {
				if (json[c] == '\\' && c + 1 < json.size()) {
					char n = json[c + 1];
					out.push_back(n == 'n' ? '\n' : n == 't' ? '\t' : n);
					c += 2;
				} else {
					out.push_back(json[c]);
					c++;
				}
			}
			return true;
		} else if (json[c] == '[' || json[c] == '{') {
			was_string = false;
			char open = json[c], close = (open == '[') ? ']' : '}';
			int depth = 0;
			size_t start = c;
			for (; c < json.size(); c++) {
				if (json[c] == open)
					depth++;
				else if (json[c] == close) {
					depth--;
					if (depth == 0) {
						c++;
						break;
					}
				}
			}
			out = json.substr(start, c - start);
			return true;
		} else {
			was_string = false;
			out.clear();
			while (c < json.size() && json[c] != ',' && json[c] != '}' && json[c] != ' ' && json[c] != '\n' &&
			       json[c] != '\r' && json[c] != '\t') {
				out.push_back(json[c]);
				c++;
			}
			return true;
		}
	}
	return false;
}

// ---- signature verification ------------------------------------------------

inline bool VerifyHS256(const std::string &signing_input, const std::string &sig, const std::string &secret) {
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
	     reinterpret_cast<const unsigned char *>(signing_input.data()), signing_input.size(), mac, &len);
	if (len != sig.size())
		return false;
	return CRYPTO_memcmp(mac, sig.data(), len) == 0;
}

inline bool VerifyRS256(const std::string &signing_input, const std::string &sig, const JwkKey &key) {
	std::string n_raw, e_raw;
	if (!B64UrlDecode(key.n_b64url, n_raw) || !B64UrlDecode(key.e_b64url, e_raw))
		return false;
	BIGNUM *n = BN_bin2bn(reinterpret_cast<const unsigned char *>(n_raw.data()), static_cast<int>(n_raw.size()), nullptr);
	BIGNUM *e = BN_bin2bn(reinterpret_cast<const unsigned char *>(e_raw.data()), static_cast<int>(e_raw.size()), nullptr);
	if (!n || !e) {
		BN_free(n);
		BN_free(e);
		return false;
	}
	EVP_PKEY *pkey = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
	if (pctx && params) {
		EVP_PKEY_fromdata_init(pctx);
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
	}
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(pctx);
	BN_free(n);
	BN_free(e);
#else
	RSA *rsa = RSA_new();
	RSA_set0_key(rsa, n, e, nullptr); // takes ownership of n, e
	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);
#endif
	if (!pkey)
		return false;

	bool ok = false;
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (md && EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
	    EVP_DigestVerifyUpdate(md, signing_input.data(), signing_input.size()) == 1) {
		ok = EVP_DigestVerifyFinal(md, reinterpret_cast<const unsigned char *>(sig.data()), sig.size()) == 1;
	}
	EVP_MD_CTX_free(md);
	EVP_PKEY_free(pkey);
	return ok;
}

// ---- top-level verify ------------------------------------------------------

// `now_us` is epoch microseconds (caller supplies it; the hooks read DuckDB's
// clock). Validates signature (per mode), exp, iss, and aud. Returns Claims.
inline Claims VerifyJwt(const std::string &token, State &st, int64_t now_us) {
	Claims c;
	size_t d1 = token.find('.');
	size_t d2 = (d1 == std::string::npos) ? std::string::npos : token.find('.', d1 + 1);
	if (d1 == std::string::npos || d2 == std::string::npos) {
		c.error = "malformed";
		return c;
	}
	std::string h_b64 = token.substr(0, d1);
	std::string p_b64 = token.substr(d1 + 1, d2 - d1 - 1);
	std::string s_b64 = token.substr(d2 + 1);
	std::string signing_input = token.substr(0, d2);

	std::string header_json, payload_json, sig;
	if (!B64UrlDecode(h_b64, header_json) || !B64UrlDecode(p_b64, payload_json) || !B64UrlDecode(s_b64, sig)) {
		c.error = "b64";
		return c;
	}

	AuthMode mode = st.Mode();
	if (mode == AuthMode::HS256) {
		if (!VerifyHS256(signing_input, sig, st.Secret())) {
			c.error = "bad_sig";
			return c;
		}
	} else if (mode == AuthMode::RS256) {
		std::string kid, dummy;
		bool s = false;
		JsonField(header_json, "kid", kid, s);
		JwkKey key;
		if (!st.FindJwk(kid, key)) {
			c.error = "unknown_kid";
			return c;
		}
		if (!VerifyRS256(signing_input, sig, key)) {
			c.error = "bad_sig";
			return c;
		}
	} // DEV: no signature check.

	// Claims.
	bool was_str = false;
	JsonField(payload_json, "sub", c.sub, was_str);
	JsonField(payload_json, "jti", c.jti, was_str);
	JsonField(payload_json, "iss", c.iss, was_str);
	JsonField(payload_json, "aud", c.aud_raw, was_str);
	std::string exp_str;
	if (JsonField(payload_json, "exp", exp_str, was_str) && !exp_str.empty()) {
		c.exp_us = static_cast<int64_t>(strtoll(exp_str.c_str(), nullptr, 10)) * 1000000LL;
	}

	if (c.sub.empty()) {
		c.error = "no_sub";
		return c;
	}
	if (c.exp_us != 0 && now_us > c.exp_us) {
		c.error = "expired";
		return c;
	}
	if (mode != AuthMode::DEV) {
		std::string want_iss = st.Issuer();
		if (!want_iss.empty() && c.iss != want_iss) {
			c.error = "bad_iss";
			return c;
		}
		std::string want_aud = st.Audience();
		if (!want_aud.empty() && c.aud_raw.find(want_aud) == std::string::npos) {
			c.error = "bad_aud";
			return c;
		}
	}
	c.ok = true;
	return c;
}

} // namespace birdshot
