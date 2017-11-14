/*
  cw-utils - utilities for cert-whisperer

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

#include <string.h>
#include <stdio.h>

#include <jansson.h>


#include <cert-whisperer.h>


int
  parse_config
    (CW_CONTEXT
      *ctx)

{ /* parse_config */

  char
    field [1024];
  int
    found_field;
  int
    status;
  json_t
    *value;


  status = STCW_OK;
  found_field = 0;

  // ca-template is the template used to create the config file

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "ca-template");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->CA_template, json_string_value (value));
  };

  // cert-command is what to do 

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "cert-command");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    if (0 EQUALS strcmp ("issue", json_string_value (value)))
      ctx->cert_command = CW_CMD_ISSUE_CERT;  
    if (0 EQUALS strcmp ("sign", json_string_value (value)))
      ctx->cert_command = CW_CMD_SIGN;  
  };

  // cert-name is the (file) name used for this certificate

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "cert-name");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->cert_name, json_string_value (value));
  };

  // extensions is the (file) name used for this certificate

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "extensions");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->ca_specs_1, json_string_value (value));
  };

  // nopw causes no password; pw= causes passphrase

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "nopw");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    ctx->option_pw_privkey = 0;
  };

  // san-email is the subjectAltName RFC822name (we allow only one)

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "san-email");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->san_email, json_string_value (value));
  };

  // privkey is the private key password

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "privkey");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    ctx->option_pw_privkey = 1;
    strcpy (ctx->private_key_passphrase, json_string_value (value));
  };

  // subject is the CA subjectName

  if (status EQUALS STCW_OK)
  {
    found_field = 1;
    strcpy (field, "subject");
    value = json_object_get (ctx->root, field);
    if (!json_is_string (value))
      found_field = 0;
  };
  if (found_field)
  {
    strcpy (ctx->subject, json_string_value (value));
  };

  return (status);

} /* parse_config */


int
  setup_config
    (CW_CONTEXT
      *ctx)

{ /* setup_config */

  char
    command [1024];
  char
    last_temp [1024];
  char
    previous_temp [1024];
  int
    status;


  status = STCW_OK;
  strcpy (last_temp, template_name (ctx, "1"));
  sprintf (command, "sed -e \"s/CW_DIRECTORY/%s/g\" <%s >%s",
    ctx->CA_directory, ctx->CA_template, last_temp);
  if (ctx->verbosity > 3)
    fprintf (stderr, "Cmd: %s\n", command);
  system (command);
  if (strlen (ctx->san_email) > 0)
  {
    strcpy (previous_temp, last_temp);
    strcpy (last_temp, template_name (ctx, "2"));
    sprintf (command, "sed -e \"s/CW_SAN_EMAIL/%s/g\" <%s >%s",
      ctx->san_email, previous_temp, last_temp);
    system (command);
  };
  sprintf (command, "cp %s %s",
    last_temp, ctx->openssl_config_path);
  if (ctx->verbosity > 3)
    fprintf (stderr, "Cmd: %s\n", command);
  system (command);
  return (status);

} /* setup_config */


char *template_name
    (CW_CONTEXT
      *ctx,
    char
      *suffix)

{ /* template_name */

  static char
    tname [1024];


  sprintf (tname, "%s_%s", ctx->temp_base, suffix);
  return (tname);

} /* template_name */

