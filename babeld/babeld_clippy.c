/* babel_diversity_factor => "[no] babel diversity-factor (1-256)$factor" */
DEFUN_CMD_FUNC_DECL(babel_diversity_factor)
#define funcdecl_babel_diversity_factor static int babel_diversity_factor_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t factor,\
	const char * factor_str __attribute__ ((unused)))
funcdecl_babel_diversity_factor;
DEFUN_CMD_FUNC_TEXT(babel_diversity_factor)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t factor = 0;
	const char *factor_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "factor")) {
			factor_str = argv[_i]->arg;
			char *_end;
			factor = strtoll(argv[_i]->arg, &_end, 10);
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
	if (!factor_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "factor_str");
		return CMD_WARNING;
	}

	return babel_diversity_factor_magic(self, vty, argc, argv, no, factor, factor_str);
}

/* babel_set_resend_delay => "[no] babel resend-delay (20-655340)$delay" */
DEFUN_CMD_FUNC_DECL(babel_set_resend_delay)
#define funcdecl_babel_set_resend_delay static int babel_set_resend_delay_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t delay,\
	const char * delay_str __attribute__ ((unused)))
funcdecl_babel_set_resend_delay;
DEFUN_CMD_FUNC_TEXT(babel_set_resend_delay)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t delay = 0;
	const char *delay_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "delay")) {
			delay_str = argv[_i]->arg;
			char *_end;
			delay = strtoll(argv[_i]->arg, &_end, 10);
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
	if (!delay_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "delay_str");
		return CMD_WARNING;
	}

	return babel_set_resend_delay_magic(self, vty, argc, argv, no, delay, delay_str);
}

/* babel_set_smoothing_half_life => "[no] babel smoothing-half-life (0-65534)$seconds" */
DEFUN_CMD_FUNC_DECL(babel_set_smoothing_half_life)
#define funcdecl_babel_set_smoothing_half_life static int babel_set_smoothing_half_life_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	int64_t seconds,\
	const char * seconds_str __attribute__ ((unused)))
funcdecl_babel_set_smoothing_half_life;
DEFUN_CMD_FUNC_TEXT(babel_set_smoothing_half_life)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	int64_t seconds = 0;
	const char *seconds_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = (argv[_i]->type == WORD_TKN) ? argv[_i]->text : argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "seconds")) {
			seconds_str = argv[_i]->arg;
			char *_end;
			seconds = strtoll(argv[_i]->arg, &_end, 10);
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
	if (!seconds_str) {
		vty_out(vty, "Internal CLI error [%s]\n", "seconds_str");
		return CMD_WARNING;
	}

	return babel_set_smoothing_half_life_magic(self, vty, argc, argv, no, seconds, seconds_str);
}

