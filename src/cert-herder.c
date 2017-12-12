#include <stdio.h>
#include <string.h>

#include <getopt.h>
extern char *optarg;
extern int optind;

#define EQUALS ==

#define CW_NOOP (0)
#define CW_EMAIL (1)
#define CW_SUBJECT (2)
#define CW_CERTNAME (3)
#define CW_DAYS (4)
#define CW_HELP (99)

typedef struct cw_context {
  FILE *config;
  char command[1024];
} CW_CONTEXT;

#define ST_OK (0)
int output_config(CW_CONTEXT *ctx, char *config);

char param_CA[1024];
char param_CA_template[1024];
char param_certname[1024];
char param_config_file[1024];
char param_days[1024];
char param_email[1024];
char param_extensions[1024];
char param_subject[1024];
char param_config_file[1024];
char param_config_file[1024];

int initialize(CW_CONTEXT *ctx, int argc, char *argv[])

{ /* initialize */

  int action;
  int done;
  int found_something;
  int longindex;
  struct option longopts[] = {
    {"certname", required_argument, &action, CW_CERTNAME},
    {"email", required_argument, &action, CW_EMAIL},
    {"subject", required_argument, &action, CW_SUBJECT},
    {0, 0, 0, 0}};
  char optstring[1024];
  int status;
  int status_opt;

  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
  done = 0;
  found_something = 0;
  while (!done)
  {
    action = CW_NOOP;
    status_opt = getopt_long(argc, argv, optstring, longopts, &longindex);
    if (!found_something)
      if (status_opt EQUALS - 1)
        action = CW_HELP;
    // action was set by getopt_long using longopts...
    switch (action)
    {
    case CW_HELP:
      found_something = 1;
    default:
      fprintf(stderr, "cert-herder help\n");
      fprintf(stderr, "  --email=user@example.com\n");
      fprintf(stderr,
              "  --subject=/C=US/ST=DC/L=Washington/O=org/OU=dept/CN=thing\n");
      break;
    case CW_CERTNAME:
      found_something = 1;
      strcpy(param_certname, optarg);
      break;
    case CW_DAYS:
      found_something = 1;
      strcpy(param_days, optarg);
      break;
    case CW_EMAIL:
      found_something = 1;
      strcpy(param_email, optarg);
      break;
    case CW_NOOP:
      break;
    case CW_SUBJECT:
      found_something = 1;
      strcpy(param_subject, optarg);
      break;
    };
    if (status_opt EQUALS - 1)
      done = 1;
  };
  return (status);

} /* initialize */

int main(int argc, char *argv[])

{ /* cert-herder */

  FILE *config;
  CW_CONTEXT
  context;
  int status;

  strcpy(param_certname, "opsuser1");
  strcpy(param_CA, "LCBO-CA");
  strcpy(param_CA_template, "./LCBO-TEMPLATE.cnf");
  strcpy(param_email, "opsuser1@example.com");
  strcpy(param_subject, "/C=US/ST=California/L=Oakland/O=Example "
                        "Organization/OU=LCBO/CN=User1 Operations1");
  strcpy(param_extensions, "usr_smime_cert");
  status = initialize(&context, argc, argv);
  config = fopen(param_config_file, "w");
  context.config = config;
  strcpy(context.command, "issue");
  if (status EQUALS ST_OK)
    status = output_config(&context, "1.json");
  strcpy(context.command, "sign");
  if (status EQUALS ST_OK)
    status = output_config(&context, "2.json");

  return (status);
}

int output_config(CW_CONTEXT *ctx, char *config_file)

{ /* output_config */

  int status;

  status = ST_OK;

  ctx->config = fopen(config_file, "w");
  if (ctx->config EQUALS NULL)
  { status = -1; };

  if (status EQUALS ST_OK)
  {
    fprintf(ctx->config, "{\n");
    fprintf(ctx->config, "  \"cert-name\" : \"%s\",\n", param_certname);
    fprintf(ctx->config, "  \"cert-command\" : \"%s\",\n", ctx->command);
    fprintf(ctx->config, "  \"download\" : \"%s\",\n", param_CA);
    fprintf(ctx->config, "  \"ca-template\" : \"%s\",\n", param_CA_template);
    fprintf(ctx->config, "  \"subject\" : \"%s\"\n,", param_subject);
    fprintf(ctx->config, "  \"san-email\" : \"%s\"\n,", param_email);
    fprintf(ctx->config, "  \"days\" : \"%s\"\n", param_days);
    fprintf(ctx->config, "  \"extensions\" : \"%s\",\n", param_extensions);
    fprintf(ctx->config, "  \"#\" : \"_the-end\"\n");
    fprintf(ctx->config, "}\n");
    fclose(ctx->config);
  };
  return (status);

} /* output_config */
