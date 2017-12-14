/*
  cw-signer - signer (i.e CA engine) routines

  (C)Copyright 2017 Smithee Solutions LLC

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

#include <jansson.h>

#include <cert-whisperer.h>

int cw_sign(CW_CONTEXT *ctx)

{ /* cw_sign */

  char command[1024];
  int status;

  status = STCW_OK;
  sprintf(command,
          "openssl ca -config %s -batch -key %s_key.pem -extensions %s -out "
          "%s_cert.pem -infiles %s_req.pem",
          ctx->openssl_config_path, ctx->cert_name, ctx->ca_specs_1,
          ctx->cert_name, ctx->cert_name);
  if (ctx->verbosity > 3)
    fprintf(stderr, "Command is: %s\n", command);
  system(command);
  return (status);

} /* cw_sign */
