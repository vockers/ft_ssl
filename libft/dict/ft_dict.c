/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_dict.c                                          :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/12/17 16:22:17 by vockers       #+#    #+#                 */
/*   Updated: 2023/12/17 16:22:17 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_dict	*ft_dict_create(void)
{
	t_dict	*dict;

	dict = malloc(sizeof(t_dict));
	if (dict == NULL)
		return (NULL);
	dict->entries = ft_calloc(DEFAULT_CAPACITY, sizeof(t_dict_entry));
	if (dict->entries == NULL)
	{
		free(dict);
		return (NULL);
	}
	dict->length = 0;
	dict->capacity = DEFAULT_CAPACITY;
	return (dict);
}

void	*ft_dict_get(t_dict *dict, const char *key)
{
	size_t	index;

	index = ft_dict_index(key, dict->capacity);
	while (dict->entries[index].key != NULL)
	{
		if (ft_strcmp(key, dict->entries[index].key) == 0)
			return (dict->entries[index].value);
		index++;
		if (index >= dict->capacity)
			index = 0;
	}
	return (NULL);
}

int	ft_dict_set(t_dict *dict, const char *key, void *value)
{
	if (dict == NULL)
		return (-1);
	if (dict->length >= dict->capacity / 2)
	{
		if (!ft_dict_expand(dict))
			return (-1);
	}
	return (ft_dict_set_entry(dict->entries, dict->capacity, \
		(t_dict_entry){(char *)key, value}, &(dict->length)));
}

void	ft_dict_free(t_dict *dict)
{
	size_t	i;

	i = 0;
	while (i < dict->capacity)
	{
		if (dict->entries[i].key != NULL)
			free(dict->entries[i].key);
		i++;
	}
	free(dict->entries);
	free(dict);
}
