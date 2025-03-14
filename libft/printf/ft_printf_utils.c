/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf_utils.c                                  :+:    :+:            */
/*                                                     +:+                    */
/*   By: vincent <vincent@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/11/11 15:18:08 by vincent       #+#    #+#                 */
/*   Updated: 2023/11/11 15:18:08 by vincent       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_print_output(char *output, size_t len, int fd)
{
	int	ret_len;

	if (output == NULL)
		return (-1);
	ret_len = write(fd, output, len);
	free(output);
	return (ret_len);
}

char	*ft_output_append_format(char *output, const char **format,
									size_t *len, size_t format_len)
{
	char	*ret;

	ret = ft_strnjoin(output, *format, *len, format_len);
	free(output);
	*format += format_len;
	*len += format_len;
	return (ret);
}

char	*ft_output_append_arg(char *output, char *arg,
								size_t *s1_len, t_format format)
{
	char	*ret;
	size_t	len;

	if (arg == NULL)
	{
		if (output)
			ft_print_output(output, *s1_len, STDERR_FILENO);
		free(arg);
		return (NULL);
	}
	if (format.specifier == 'c')
	{
		if (format.width > 1)
			len = format.width;
		else
			len = 1;
	}
	else
		len = ft_strlen(arg);
	ret = ft_strnjoin(output, arg, *s1_len, len);
	free(output);
	free(arg);
	*s1_len += len;
	return (ret);
}
