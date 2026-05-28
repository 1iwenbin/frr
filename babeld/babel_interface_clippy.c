/* babel_set_wired => "[no] babel wired" */
DEFUN_CMD_FUNC_DECL(babel_set_wired)
#define funcdecl_babel_set_wired static int babel_set_wired_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no)
funcdecl_babel_set_wired;
DEFUN_CMD_FUNC_TEXT(babel_set_wired)
{
#if 1 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif

	return babel_set_wired_magic(self, vty, argc, argv, no);
}

/* babel_set_wireless => "[no] babel wireless" */
DEFUN_CMD_FUNC_DECL(babel_set_wireless)
#define funcdecl_babel_set_wireless static int babel_set_wireless_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no)
funcdecl_babel_set_wireless;
DEFUN_CMD_FUNC_TEXT(babel_set_wireless)
{
#if 1 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif

	return babel_set_wireless_magic(self, vty, argc, argv, no);
}

/* babel_split_horizon => "[no] babel split-horizon" */
DEFUN_CMD_FUNC_DECL(babel_split_horizon)
#define funcdecl_babel_split_horizon static int babel_split_horizon_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no)
funcdecl_babel_split_horizon;
DEFUN_CMD_FUNC_TEXT(babel_split_horizon)
{
#if 1 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif

	return babel_split_horizon_magic(self, vty, argc, argv, no);
}

/* babel_set_hello_interval => "[no] babel hello-interval (20-655340)" */
DEFUN_CMD_FUNC_DECL(babel_set_hello_interval)
#define funcdecl_babel_set_hello_interval static int babel_set_hello_interval_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t hello_interval,\
	const char * hello_interval_str __attribute__ ((unused)))
funcdecl_babel_set_hello_interval;
DEFUN_CMD_FUNC_TEXT(babel_set_hello_interval)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t hello_interval = 0;
	const char *hello_interval_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "hello_interval")) {
			hello_interval_str = argv[_i]->arg;
			char *_end;
			hello_interval = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!hello_interval_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "hello_interval_str");
		return CMD_WARNING;
	}

	return babel_set_hello_interval_magic(self, vty, argc, argv, no, hello_interval, hello_interval_str);
}

/* babel_set_update_interval => "[no] babel update-interval (20-655340)" */
DEFUN_CMD_FUNC_DECL(babel_set_update_interval)
#define funcdecl_babel_set_update_interval static int babel_set_update_interval_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t update_interval,\
	const char * update_interval_str __attribute__ ((unused)))
funcdecl_babel_set_update_interval;
DEFUN_CMD_FUNC_TEXT(babel_set_update_interval)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t update_interval = 0;
	const char *update_interval_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "update_interval")) {
			update_interval_str = argv[_i]->arg;
			char *_end;
			update_interval = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!update_interval_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "update_interval_str");
		return CMD_WARNING;
	}

	return babel_set_update_interval_magic(self, vty, argc, argv, no, update_interval, update_interval_str);
}

/* babel_set_rxcost => "[no] babel rxcost (1-65534)" */
DEFUN_CMD_FUNC_DECL(babel_set_rxcost)
#define funcdecl_babel_set_rxcost static int babel_set_rxcost_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t rxcost,\
	const char * rxcost_str __attribute__ ((unused)))
funcdecl_babel_set_rxcost;
DEFUN_CMD_FUNC_TEXT(babel_set_rxcost)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t rxcost = 0;
	const char *rxcost_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rxcost")) {
			rxcost_str = argv[_i]->arg;
			char *_end;
			rxcost = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!rxcost_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "rxcost_str");
		return CMD_WARNING;
	}

	return babel_set_rxcost_magic(self, vty, argc, argv, no, rxcost, rxcost_str);
}

/* babel_set_rtt_decay => "[no] babel rtt-decay (1-256)" */
DEFUN_CMD_FUNC_DECL(babel_set_rtt_decay)
#define funcdecl_babel_set_rtt_decay static int babel_set_rtt_decay_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t rtt_decay,\
	const char * rtt_decay_str __attribute__ ((unused)))
funcdecl_babel_set_rtt_decay;
DEFUN_CMD_FUNC_TEXT(babel_set_rtt_decay)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t rtt_decay = 0;
	const char *rtt_decay_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rtt_decay")) {
			rtt_decay_str = argv[_i]->arg;
			char *_end;
			rtt_decay = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!rtt_decay_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "rtt_decay_str");
		return CMD_WARNING;
	}

	return babel_set_rtt_decay_magic(self, vty, argc, argv, no, rtt_decay, rtt_decay_str);
}

/* babel_set_rtt_min => "[no] babel rtt-min (1-65535)" */
DEFUN_CMD_FUNC_DECL(babel_set_rtt_min)
#define funcdecl_babel_set_rtt_min static int babel_set_rtt_min_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t rtt_min,\
	const char * rtt_min_str __attribute__ ((unused)))
funcdecl_babel_set_rtt_min;
DEFUN_CMD_FUNC_TEXT(babel_set_rtt_min)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t rtt_min = 0;
	const char *rtt_min_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rtt_min")) {
			rtt_min_str = argv[_i]->arg;
			char *_end;
			rtt_min = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!rtt_min_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "rtt_min_str");
		return CMD_WARNING;
	}

	return babel_set_rtt_min_magic(self, vty, argc, argv, no, rtt_min, rtt_min_str);
}

/* babel_set_rtt_max => "[no] babel rtt-max (1-65535)" */
DEFUN_CMD_FUNC_DECL(babel_set_rtt_max)
#define funcdecl_babel_set_rtt_max static int babel_set_rtt_max_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t rtt_max,\
	const char * rtt_max_str __attribute__ ((unused)))
funcdecl_babel_set_rtt_max;
DEFUN_CMD_FUNC_TEXT(babel_set_rtt_max)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t rtt_max = 0;
	const char *rtt_max_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rtt_max")) {
			rtt_max_str = argv[_i]->arg;
			char *_end;
			rtt_max = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!rtt_max_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "rtt_max_str");
		return CMD_WARNING;
	}

	return babel_set_rtt_max_magic(self, vty, argc, argv, no, rtt_max, rtt_max_str);
}

/* babel_set_max_rtt_penalty => "[no] babel max-rtt-penalty (0-65535)" */
DEFUN_CMD_FUNC_DECL(babel_set_max_rtt_penalty)
#define funcdecl_babel_set_max_rtt_penalty static int babel_set_max_rtt_penalty_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t max_rtt_penalty,\
	const char * max_rtt_penalty_str __attribute__ ((unused)))
funcdecl_babel_set_max_rtt_penalty;
DEFUN_CMD_FUNC_TEXT(babel_set_max_rtt_penalty)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t max_rtt_penalty = 0;
	const char *max_rtt_penalty_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "max_rtt_penalty")) {
			max_rtt_penalty_str = argv[_i]->arg;
			char *_end;
			max_rtt_penalty = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	if (!max_rtt_penalty_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "max_rtt_penalty_str");
		return CMD_WARNING;
	}

	return babel_set_max_rtt_penalty_magic(self, vty, argc, argv, no, max_rtt_penalty, max_rtt_penalty_str);
}

/* babel_set_enable_timestamps => "[no] babel enable-timestamps" */
DEFUN_CMD_FUNC_DECL(babel_set_enable_timestamps)
#define funcdecl_babel_set_enable_timestamps static int babel_set_enable_timestamps_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no)
funcdecl_babel_set_enable_timestamps;
DEFUN_CMD_FUNC_TEXT(babel_set_enable_timestamps)
{
#if 1 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif

	return babel_set_enable_timestamps_magic(self, vty, argc, argv, no);
}

/* babel_set_channel => "[no] babel channel <(1-254)$ch|interfering$interfering|noninterfering$noninterfering>" */
DEFUN_CMD_FUNC_DECL(babel_set_channel)
#define funcdecl_babel_set_channel static int babel_set_channel_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t ch,\
	const char * ch_str __attribute__ ((unused)),\
	const char * interfering,\
	const char * noninterfering)
funcdecl_babel_set_channel;
DEFUN_CMD_FUNC_TEXT(babel_set_channel)
{
#if 4 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t ch = 0;
	const char *ch_str = NULL;
	const char *interfering = NULL;
	const char *noninterfering = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "ch")) {
			ch_str = argv[_i]->arg;
			char *_end;
			ch = strtoll(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "interfering")) {
			interfering = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "noninterfering")) {
			noninterfering = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif

	return babel_set_channel_magic(self, vty, argc, argv, no, ch, ch_str, interfering, noninterfering);
}

