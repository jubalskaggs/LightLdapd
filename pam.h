/**
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_PAM_H
#define LIGHTLDAPD_PAM_H
#include <security/pam_appl.h>

int auth_pam(const char *user, const char *pw, char **msg, double *delay);
#endif  /* LIGHTLDAPD_PAM_H */
