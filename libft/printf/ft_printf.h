/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf.h                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/26 11:17:45 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/26 11:17:45 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_H
# define FT_PRINTF_H

# include <stdarg.h>
# include <stdio.h>

typedef enum e_fflags
{
	FFLAG_ALT	= 1 << 0,
	FFLAG_ZERO	= 1 << 1,
	FFLAG_SPACE	= 1 << 2,
	FFLAG_PLUS	= 1 << 3,
	FFLAG_MINUS	= 1 << 4,
}				t_fflags;

typedef struct s_format
{
	char		specifier;
	int			width;
	int			precision;
	t_fflags	flags;
}				t_format;

int			ft_printf(const char *format, ...);
int			ft_vprintf(const char *format, va_list ap);
int			ft_dprintf(int fd, const char *format, ...);

int			ft_print_output(char *output, size_t len, int fd);
char		*ft_output_append_format(char *output, const char **format,
				size_t *len, size_t format_len);
char		*ft_output_append_arg(char *output, char *arg,
				size_t *s1_len, t_format format);

t_format	ft_parse_format(char **str, va_list args);

char		*ft_apply_padding(char *str, int width, int minus);
char		*ft_apply_zero_padding(char *str, int width);
char		*ft_apply_sign(char *str, int negative, t_format fmt);
char		*ft_apply_precision(char *str, t_format fmt);
char		*ft_apply_str_precision(char *str, t_format fmt);

char		*ft_convert_arg(t_format fmt, va_list args);
char		*ft_convert_char(char c, t_format fmt);
char		*ft_convert_str(char *str, t_format fmt);
char		*ft_convert_ptr(void *ptr, t_format fmt);
char		*ft_convert_int(int i, t_format fmt);
char		*ft_convert_uint(unsigned int i, t_format fmt);
char		*ft_convert_hex(unsigned int i, t_format fmt,
				char *base, int uppercase);

#endif