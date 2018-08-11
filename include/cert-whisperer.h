/*
  cert-whisperer.h - definitions

  Copyright 2017 Smithee Solutions LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#define CW_VERSION "0.20-Build-6"

#define EQUALS ==

#define CW_CMD_ISSUE_CERT (1)
#define CW_CMD_SIGN (2)

typedef struct cw_context {
  char basename [1024];
  char CA_days[1024];
  char CA_directory[1024];
  char ca_specs_1[1024];
  char CA_template[1024];
  int cert_command;
  char cert_name[1024];
  char certificate_days[1024];
  char download_file[1024];
  char ecc_curve_name[1024];
  char init_parameters_path[1024];
  char openssl_config_path[1024];
  int option_pw_privkey;
  char private_key_passphrase[1024];
  char pubkey_class[1024];
  json_t *root;
  char san_email[1024];
  char san_fqdn[1024];
  char signing_options [1024];
  char subject[1024];
  char temp_base[1024];
  char temp_prefix[1024];
  int verbosity;
} CW_CONTEXT;

#define STCW_OK (0)
#define STRM_PARMFILE (1)
#define STRM_UNDERFLOW (2)
#define STRM_OVERFLOW (3)
#define STRM_ERROR (4)
#define STCW_UNIMP (5)
#define STCW_UNK_CMD (6)

int cw_sign(CW_CONTEXT *ctx);
int parse_config(CW_CONTEXT *ctx);
int setup_config(CW_CONTEXT *ctx);
char *template_name(CW_CONTEXT *ctx, char *suffix);
