/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   libft_conversions.h                                :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/19 19:04:59 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/19 19:04:59 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_CONVERSIONS_H
# define LIBFT_CONVERSIONS_H

unsigned int	ft_abs(int num);
int				ft_atoi(const char *str);
long			ft_atol(const char *str);
char			*ft_itoa(int n);
char			*ft_utoa(unsigned int num);
char			*ft_itoa_base(int n, char *base);
char			*ft_utoa_base(unsigned int n, char *base);
char			*ft_ultoa_base(unsigned long num, char *base);

#endif