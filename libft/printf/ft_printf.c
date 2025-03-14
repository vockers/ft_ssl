/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/26 11:17:42 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/26 11:17:42 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_vdprintf(int fd, const char *format, va_list ap)
{
	char		*output;
	char		*percent;
	char		*arg;
	t_format	arg_format;
	size_t		len;

	if (format == NULL)
		return (-1);
	output = ft_strdup("");
	percent = ft_strchr(format, '%');
	len = 0;
	while (percent != NULL)
	{
		output = ft_output_append_format(output, &format, \
			&len, percent - format);
		arg_format = ft_parse_format(&percent, ap);
		arg = ft_convert_arg(arg_format, ap);
		output = ft_output_append_arg(output, arg, &len, arg_format);
		if (output == NULL)
			return (-1);
		format += percent - format;
		percent = ft_strchr(format, '%');
	}
	output = ft_output_append_format(output, &format, &len, ft_strlen(format));
	return (ft_print_output(output, len, fd));
}

int	ft_printf(const char *format, ...)
{
	va_list		ap;
	int			len;

	va_start(ap, format);
	len = ft_vdprintf(STDOUT_FILENO, format, ap);
	va_end(ap);
	return (len);
}

int	ft_dprintf(int fd, const char *format, ...)
{
	va_list		ap;
	int			len;

	va_start(ap, format);
	len = ft_vdprintf(fd, format, ap);
	va_end(ap);
	return (len);
}
