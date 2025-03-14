/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_dict_utils.c                                    :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/12/17 17:47:55 by vockers       #+#    #+#                 */
/*   Updated: 2023/12/17 17:47:55 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

size_t	ft_dict_index(const char *key, size_t capacity)
{
	uint64_t	hash;

	hash = FNV_OFFSET;
	while (*key)
	{
		hash ^= (uint64_t)(*key);
		hash *= FNV_PRIME;
		key++;
	}
	return ((size_t)(hash & (uint64_t)(capacity - 1)));
}

int	ft_dict_set_entry(t_dict_entry *entries, size_t capacity, \
		t_dict_entry entry, size_t *lenptr)
{
	size_t	index;

	index = ft_dict_index(entry.key, capacity);
	while (entries[index].key != NULL)
	{
		if (ft_strcmp(entry.key, entries[index].key) == 0)
		{
			entries[index].value = entry.value;
			return (0);
		}
		index++;
		if (index >= capacity)
			index = 0;
	}
	if (lenptr != NULL)
	{
		entry.key = ft_strdup(entry.key);
		if (entry.key == NULL)
			return (-1);
		(*lenptr)++;
	}
	entries[index].key = entry.key;
	entries[index].value = entry.value;
	return (0);
}

bool	ft_dict_expand(t_dict *dict)
{
	size_t			i;
	size_t			new_capacity;
	t_dict_entry	*new_entries;
	t_dict_entry	entry;

	new_capacity = dict->capacity * 2;
	if (new_capacity < dict->capacity)
		return (false);
	new_entries = ft_calloc(new_capacity, sizeof(t_dict_entry));
	if (new_entries == NULL)
		return (false);
	i = 0;
	while (i < dict->capacity)
	{
		entry = dict->entries[i];
		if (entry.key != NULL)
			ft_dict_set_entry(new_entries, new_capacity, entry, NULL);
		i++;
	}
	free(dict->entries);
	dict->entries = new_entries;
	dict->capacity = new_capacity;
	return (true);
}
