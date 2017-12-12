/*
  configure-CA - create a CA.  Part of cert-whisperer.


  Usage

  configure-CA <openssl config file>
  assumes thing1.json is in current directory.


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

#include <stdio.h>
#include <string.h>

#include <jansson.h>

#include <cert-whisperer.h>

#define RECREATE
#define SCRUB

#define EQUALS ==

int setup_CA(CW_CONTEXT *ctx);

int main(int argc, char *argv[])

{ /* configure_ca */

  FILE *cmdf;
  CW_CONTEXT
  *ctx;
  char command[1024];
  CW_CONTEXT
  context;
  char field[1024];
  int found_field;
  char json_string[4096];
  int status;
  int status_io;
  json_error_t status_json;
  json_t *value;

  ctx = &context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 9;
  strcpy(ctx->CA_template, "/opt/tester/etc/cwCA/openssl-TEMPLATE_1.cnf");
  strcpy(ctx->temp_base, "openssl_config_temp");
  strcpy(ctx->init_parameters_path, "./CA-setup.json");
  strcpy(ctx->openssl_config_path, "/opt/tester/etc/cwCA/openssl.cnf");

  strcpy(ctx->CA_days, "32");
  strcpy(ctx->subject,
         "/C=US/ST=California/L=Oakland/O=HellaBadCA/OU=LCBO/CN=ca");
  if (argc > 1)
    strcpy(ctx->init_parameters_path, argv[1]);

  fprintf(stderr,
          "Cert Whisperer - configure and generate Certificate Authority "
          "(openssl) - %s\n",
          CW_VERSION);
  fprintf(stderr, "Init Parameters: %s\n", ctx->init_parameters_path);
  fprintf(stderr, "OpenSSL Config: %s\n", ctx->openssl_config_path);
  fprintf(stderr, "Options:");
#ifdef SCRUB
  fprintf(stderr, "+SCRUB");
#endif
#ifdef RECREATE
  fprintf(stderr, "+RECREATE");
#endif
  fprintf(stderr, "\n");
  fprintf(stderr, "Template: %s\n", ctx->CA_template);
  status = STRM_PARMFILE;
  found_field = 0;

  cmdf = fopen(ctx->init_parameters_path, "r");
  if (cmdf != NULL)
  {
    status = STCW_OK;
    memset(json_string, 0, sizeof(json_string));
    status_io =
      fread(json_string, sizeof(json_string[0]), sizeof(json_string), cmdf);
    if (status_io >= sizeof(json_string))
      status = STRM_OVERFLOW;
    if (status_io <= 0)
      status = STRM_UNDERFLOW;
  } else
  { fprintf(stderr, "Failed to open %s\n", ctx->init_parameters_path); };
  if (status EQUALS STCW_OK)
  {
    ctx->root = json_loads(json_string, 0, &status_json);
    if (!(ctx->root))
    {
      fprintf(stderr, "JSON parser failed.  String was ->\n%s<-\n",
              json_string);
      status = STRM_ERROR;
    };
  };

  // parameter "CA-dir"
  // this is the file to push to the PD

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy(field, "download");
    value = json_object_get(ctx->root, field);
    if (!json_is_string(value))
      found_field = 0;
  };
  if (found_field)
  { strcpy(ctx->CA_directory, json_string_value(value)); };

  status = parse_config(ctx);

  if (status EQUALS STCW_OK)
  {
    fprintf(stderr, "Configurator Report:\n");
    fprintf(stderr, "CA Directory: %s\n", ctx->CA_directory);
    fprintf(stderr, "  CA Subject: %s\n", ctx->subject);
  };
#ifdef RECREATE
  if (status EQUALS STCW_OK)
  {
    fprintf(stderr, "Configuring CA...\n");
    status = setup_CA(ctx);
  };
#endif
  if (status EQUALS STCW_OK)
  {
    sprintf(command,
            "openssl ca -config %s -create_serial -out %s/cacert.pem -days %s "
            "-batch -keyfile %s/private/cakey.pem -selfsign -extensions v3_ca "
            "-infiles %s/careq.pem",
            ctx->openssl_config_path, ctx->CA_directory, ctx->CA_days,
            ctx->CA_directory, ctx->CA_directory);

    fprintf(stderr, "Command is: %s\n", command);
    system(command);
  };
  if (status != STCW_OK)
    fprintf(stderr, "Returning status %d\n", status);
  return (status);

} /* configure_ca */

int setup_CA(CW_CONTEXT *ctx)

{ /* setup_CA */

  char command[1024];
  char *option_encrypt;
  int status;

  status = STCW_OK;
#ifdef SCRUB
  sprintf(command, "rm -rvf %s\n", ctx->CA_directory);
  system(command);
#endif

  status = setup_config(ctx);
  if (status EQUALS STCW_OK)
  {
    sprintf(command, "mkdir -p %s/certs\n", ctx->CA_directory);
    system(command);
    sprintf(command, "mkdir -p %s/certs\n", ctx->CA_directory);
    system(command);
    sprintf(command, "mkdir -p %s/crl\n", ctx->CA_directory);
    system(command);
    sprintf(command, "mkdir -p %s/newcerts\n", ctx->CA_directory);
    system(command);
    sprintf(command, "mkdir -p %s/private\n", ctx->CA_directory);
    system(command);
    sprintf(command, "touch %s/index.txt;echo \"01\" >%s/crlnumber",
            ctx->CA_directory, ctx->CA_directory);
    system(command);
  };

  if (status EQUALS STCW_OK)
  {
    if (!(ctx->option_pw_privkey))
    {
      option_encrypt = "-nodes";
    } else
    { status = STCW_UNIMP; };
  };
  if (status EQUALS STCW_OK)
  {
    sprintf(command,
            "openssl req -config %s %s -subj \"%s\" -new -keyout "
            "%s/private/cakey.pem -out %s/careq.pem",
            ctx->openssl_config_path, option_encrypt, ctx->subject,
            ctx->CA_directory, ctx->CA_directory);
    fprintf(stderr, "Command is: %s\n", command);
    system(command);
  };

  return (status);

} /* setup_CA */
