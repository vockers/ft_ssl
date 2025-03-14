/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_split.c                                         :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:43:42 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/03 16:33:47 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_count_words(char const *s, char c)
{
	int	count;
	int	new_word;

	count = 0;
	new_word = 1;
	while (*s)
	{
		if (*s == c)
			new_word = 1;
		else if (new_word)
		{
			count++;
			new_word = 0;
		}
		s++;
	}
	return (count);
}

static int	ft_strclen(const char *str, char c)
{
	int	len;

	len = 0;
	while (str[len] != '\0' && str[len] != c)
		len++;
	return (len);
}

static char	**ft_delete_strs(char **strs)
{
	char	**s;

	s = strs;
	while (*strs)
		free(*strs++);
	free(s);
	return (NULL);
}

char	**ft_split(char const *s, char c)
{
	char	**new;
	int		new_word;
	int		i;

	new = (char **)malloc(sizeof(char *) * (ft_count_words(s, c) + 1));
	if (!new)
		return (NULL);
	new_word = 1;
	i = 0;
	while (*s)
	{
		if (*s == c)
			new_word = 1;
		else if (new_word)
		{
			new[i] = ft_strndup(s, ft_strclen(s, c));
			if (!new[i])
				return (ft_delete_strs(new));
			new_word = 0;
			i++;
		}
		s++;
	}
	new[i] = NULL;
	return (new);
}
