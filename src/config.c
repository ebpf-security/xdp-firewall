#include <stdio.h>
#include <stdlib.h>
//#include <libconfig.h>
#include <string.h>
#include <linux/types.h>

#include <arpa/inet.h>

#include "xdpfw.h"
#include "config.h"

FILE *file;

/**
 * Sets the config structure's default values.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
*/
void setcfgdefaults(struct config *cfg)
{
    return;
}

/**
 * Opens the config file.
 * 
 * @param filename Path to config file.
 * 
 * @return 0 on success or 1 on error.
*/
int opencfg(const char *filename)
{


    return 0;
}

/**
 * Read the config file and stores values in config structure.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return 0 on success or 1/-1 on error.
*/
int readcfg(struct config *cfg)
{
      return 0;
}