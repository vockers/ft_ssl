/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   libft_ctype.h                                      :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/19 18:59:29 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/19 18:59:29 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_CTYPE_H
# define LIBFT_CTYPE_H

enum
{
	LIBFT_IS_ALNUM	= 1 << 3,
	LIBFT_IS_ALPHA	= 1 << 10,
	LIBFT_IS_DIGIT	= 1 << 11,
	LIBFT_IS_SPACE	= 1 << 13,
	LIBFT_IS_PRINT	= 1 << 14
};

int		ft_isalpha(int c);
int		ft_isdigit(int c);
int		ft_isalnum(int c);
int		ft_isascii(int c);
int		ft_isprint(int c);
int		ft_isspace(int c);
int		ft_toupper(int c);
int		ft_tolower(int c);

#endif