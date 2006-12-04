/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: January 22, 2004
 */

#ifndef SEAUDIT_CALLBACK_H
#define SEAUDIT_CALLBACK_H

typedef void (*seaudit_callback_t) (void *user_data);

typedef struct registered_callback
{
	seaudit_callback_t function;
	void *user_data;
	unsigned int type;

/* callback types */
#define POLICY_LOADED_CALLBACK   0
#define LOG_LOADED_CALLBACK      1
#define LOG_FILTERED_CALLBACK    2

/* signal types */
#define POLICY_LOADED_SIGNAL POLICY_LOADED_CALLBACK
#define LOG_LOADED_SIGNAL    LOG_LOADED_CALLBACK
#define LOG_FILTERED_SIGNAL  LOG_FILTERED_CALLBACK
} registered_callback_t;

/* callback and signal handling for seaudit events */
int seaudit_callback_register(seaudit_callback_t function, void *user_data, unsigned int type);
void seaudit_callback_remove(seaudit_callback_t function, void *user_data, unsigned int type);
void seaudit_callbacks_free(void);
void seaudit_callback_signal_emit(unsigned int type);

#define policy_load_callback_register(function, user_data) seaudit_callback_register(function, user_data, POLICY_LOADED_CALLBACK)
#define policy_load_callback_remove(function, user_data) seaudit_callback_remove(function, user_data, POLICY_LOADED_CALLBACK)
#define policy_load_signal_emit() seaudit_callback_signal_emit(POLICY_LOADED_SIGNAL)
#define log_load_callback_register(function, user_data) seaudit_callback_register(function, user_data, LOG_LOADED_CALLBACK)
#define log_load_callback_remove(function, user_data) seaudit_callback_remove(function, user_data, LOG_LOADED_CALLBACK)
#define log_load_signal_emit() seaudit_callback_signal_emit(LOG_LOADED_SIGNAL)
#define log_filtered_callback_register(function, user_data) seaudit_callback_register(function, user_data, LOG_FILTERED_CALLBACK)
#define log_filtered_callback_remove(function, user_data) seaudit_callback_remove(function, user_data, LOG_FILTERED_CALLBACK)
#define log_filtered_signal_emit() seaudit_callback_signal_emit(LOG_FILTERED_SIGNAL)

#endif
