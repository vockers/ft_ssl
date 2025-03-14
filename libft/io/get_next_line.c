/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   get_next_line.c                                    :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/20 15:20:30 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/20 15:20:30 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

#define BUFFER_SIZE	1024
#define MAX_FD		1024

static void	free_null(char **ptr)
{
	if (*ptr)
	{
		free(*ptr);
		*ptr = NULL;
	}
}

char	*create_line(int nl_position, char **buffer)
{
	char	*res;
	char	*tmp;

	if (nl_position == 0)
	{
		if (**buffer == '\0')
			return (free_null(buffer), NULL);
		res = *buffer;
		*buffer = NULL;
		return (res);
	}
	res = ft_substr(*buffer, 0, nl_position);
	if (res == NULL)
		return (free_null(buffer), NULL);
	tmp = *buffer;
	*buffer = ft_substr(*buffer, nl_position, BUFFER_SIZE);
	free(tmp);
	if (*buffer == NULL)
		return (free_null(&res), NULL);
	return (res);
}

char	*read_line(int fd, char **buffer, char *read_buffer)
{
	ssize_t	bytes_read;
	char	*new_line;
	char	*tmp;

	new_line = ft_strchr(*buffer, '\n');
	while (new_line == NULL)
	{
		bytes_read = read(fd, read_buffer, BUFFER_SIZE);
		if (bytes_read < 0)
			return (free_null(buffer), NULL);
		if (bytes_read == 0)
			return (create_line(0, buffer));
		read_buffer[bytes_read] = '\0';
		tmp = *buffer;
		*buffer = ft_strjoin(*buffer, read_buffer);
		free(tmp);
		if (*buffer == NULL)
			return (NULL);
		new_line = ft_strchr(*buffer, '\n');
	}
	return (create_line(new_line - *buffer + 1, buffer));
}

char	*get_next_line(int fd)
{
	static char	*buffers[MAX_FD + 1] = {NULL};
	char		*line;
	char		*read_buffer;

	if (fd < 0 || BUFFER_SIZE <= 0 || fd >= MAX_FD)
		return (NULL);
	read_buffer = (char *)malloc(sizeof(char) * (BUFFER_SIZE + 1));
	if (read_buffer == NULL)
		return (free_null(&buffers[fd]), NULL);
	if (buffers[fd] == NULL)
	{
		buffers[fd] = ft_strdup("");
		if (buffers[fd] == NULL)
			return (free_null(&read_buffer), NULL);
	}
	line = read_line(fd, &buffers[fd], read_buffer);
	free(read_buffer);
	read_buffer = NULL;
	return (line);
}
