/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   libft_dict.h                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/12/17 13:42:33 by vockers       #+#    #+#                 */
/*   Updated: 2023/12/17 13:42:33 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_DICT_H
# define LIBFT_DICT_H

# include <stdlib.h>

# define DEFAULT_CAPACITY 32

typedef struct s_dict_entry
{
	char			*key;
	void			*value;
}	t_dict_entry;

typedef struct s_dict
{
	t_dict_entry	*entries;
	size_t			capacity;
	size_t			length;
}	t_dict;

t_dict			*ft_dict_create(void);
void			ft_dict_free(t_dict *dict);
void			*ft_dict_get(t_dict *dict, const char *key);
int				ft_dict_set(t_dict *dict, const char *key, void *value);

size_t			ft_dict_index(const char *key, size_t capacity);
int				ft_dict_set_entry(t_dict_entry *entries, size_t capacity, \
					t_dict_entry entry, size_t *lenptr);
bool			ft_dict_expand(t_dict *dict);

#endif