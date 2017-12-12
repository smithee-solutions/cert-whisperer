/*
  cert-whisper - manage certificates.  Part of cert-whisperer.


  Usage

  cert-whisper [cert whisperer json parameter file]
  assumes cert-whisper.json in current directory as default.


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

int main(int argc, char *argv[])

{ /* main for cert-whisper */

  FILE *cmdf;
  CW_CONTEXT
  *ctx;
  char command[1024];
  CW_CONTEXT
  context;
  char field[1024];
  int found_field;
  char json_string[4096];
  char *option_encrypt;
  int status;
  int status_io;
  json_error_t status_json;
  json_t *value;

  ctx = &context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 9;
  strcpy(ctx->temp_base, "openssl_config_temp");
  strcpy(ctx->init_parameters_path, "./cert-whisper.json");
  strcpy(ctx->openssl_config_path, "/opt/tester/etc/cwCA/openssl.cnf");
  strcpy(ctx->cert_name, "user");
  strcpy(ctx->ca_specs_1, "usr_cert");

  if (argc > 1)
    strcpy(ctx->init_parameters_path, argv[1]);

  fprintf(stderr, "cert-whisper: manage certificates - %s\n", CW_VERSION);
  fprintf(stderr, "Init Parameters: %s\n", ctx->init_parameters_path);
  fprintf(stderr, " OpenSSL Config: %s\n", ctx->openssl_config_path);
  fprintf(stderr, "        Options:");

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
    fprintf(stderr, "Configuration.\n");
    fprintf(stderr, "   CA Directory: %s\n", ctx->CA_directory);
    fprintf(stderr, "        Subject: %s\n", ctx->subject);
    fprintf(stderr, "     Extensions: %s\n", ctx->ca_specs_1);
    if (strlen(ctx->san_email) > 0)
      fprintf(stderr, " SAN RFC822Name: %s\n", ctx->san_email);
  };
  if (status EQUALS STCW_OK)
    status = setup_config(ctx);
  if (status EQUALS STCW_OK)
  {
    switch (ctx->cert_command)
    {
    case CW_CMD_ISSUE_CERT:
      option_encrypt = "";
      if (!(ctx->option_pw_privkey))
      {
        option_encrypt = "-nodes";
      } else
      { status = STCW_UNIMP; };
      if (strncmp (ctx->pubkey_class, "ecc", 3) EQUALS 0)
      {
        sprintf(command,
               "openssl ecparam -out %s_key.pem -name %s -genkey",
               ctx->cert_name, ctx->ecc_curve_name);
        if (ctx->verbosity > 3)
        {
          fprintf(stderr, "Command is: %s\n", command);
          system(command);
        };
        sprintf(command,
                "openssl req -config %s %s -subj \"%s\" -new -key %s_key.pem "
                "-out %s_req.pem",
                ctx->openssl_config_path, option_encrypt, ctx->subject,
                ctx->cert_name, ctx->cert_name);
        if (ctx->verbosity > 3)
          fprintf(stderr, "Command is: %s\n", command);
        system(command);
      }
      else
      {
        // not ECC
        sprintf(command,
                "openssl req -config %s %s -subj \"%s\" -new -keyout %s_key.pem "
                "-out %s_req.pem",
                ctx->openssl_config_path, option_encrypt, ctx->subject,
                ctx->cert_name, ctx->cert_name);
        if (ctx->verbosity > 3)
          fprintf(stderr, "Command is: %s\n", command);
        system(command);
      };
      break;

    case CW_CMD_SIGN:
#if 0
      sprintf (command,
"openssl ca -config %s -batch -key %s_key.pem -extensions %s -infiles %s_req.pem",
        ctx->openssl_config_path, ctx->cert_name, ctx->ca_specs_1, ctx->cert_name);
      if (ctx->verbosity > 3)
        fprintf (stderr, "Command is: %s\n", command);
      system (command);
#endif
      status = cw_sign(ctx);
      break;

    default:
      fprintf(stderr, "Unknown cert-whisperer command (%d)\n",
              ctx->cert_command);
      status = STCW_UNK_CMD;
      break;
    };
  };
  if (status != STCW_OK)
    fprintf(stderr, "Returning status %d\n", status);
  return (status);

} /* main for cert-whisper */
