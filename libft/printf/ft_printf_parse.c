/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf_parse.c                                  :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/26 11:17:48 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/26 11:17:48 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	is_flag(char c)
{
	if (c == '#')
		return (FFLAG_ALT);
	if (c == '0')
		return (FFLAG_ZERO);
	if (c == ' ')
		return (FFLAG_SPACE);
	if (c == '+')
		return (FFLAG_PLUS);
	if (c == '-')
		return (FFLAG_MINUS);
	return (0);
}

static int	parse_flags(char **str)
{
	int	flags;

	flags = 0;
	while (is_flag(**str))
	{
		flags |= is_flag(**str);
		(*str)++;
	}
	return (flags);
}

static int	parse_width(char **str)
{
	int	width;

	width = 0;
	if (**str >= '1' && **str <= '9')
	{
		width = **str - '0';
		(*str)++;
		while (ft_isdigit(**str))
		{
			width = width * 10 + **str - '0';
			(*str)++;
		}
	}
	return (width);
}

static int	parse_precision(char **str, va_list args)
{
	int	precision;

	precision = -1;
	if (**str == '.')
	{
		precision = 0;
		(*str)++;
		if (**str == '*')
		{
			precision = va_arg(args, int);
			(*str)++;
			return (precision);
		}
		while (ft_isdigit(**str))
		{
			precision = precision * 10 + **str - '0';
			(*str)++;
		}
	}
	return (precision);
}

t_format	ft_parse_format(char **str, va_list args)
{
	t_format	format;

	(*str)++;
	format.flags = parse_flags(str);
	format.width = parse_width(str);
	format.precision = parse_precision(str, args);
	format.specifier = **str;
	(*str)++;
	return (format);
}
